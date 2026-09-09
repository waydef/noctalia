#include "auth/pam_authenticator.h"

#include "core/log.h"
#include "i18n/i18n.h"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

  constexpr Logger kLog("pam");

  constexpr std::size_t kMaxPamMessageBytes = 4096;

  void secureClear(std::string& value) {
    if (!value.empty() || value.capacity() > 0) {
      ::explicit_bzero(value.data(), value.capacity());
    }
    value.clear();
  }

  struct PamConversationData {
    const char* password = nullptr;
    bool passwordConsumed = false;
  };

  struct PamHandle {
    pam_handle_t* h = nullptr;
    int lastRc = PAM_SUCCESS;

    PamHandle() = default;
    PamHandle(const PamHandle&) = delete;
    PamHandle& operator=(const PamHandle&) = delete;

    ~PamHandle() {
      if (h != nullptr) {
        pam_end(h, lastRc);
      }
    }
  };

  int pamConversation(int numMsg, const pam_message** msg, pam_response** response, void* appdataPtr) {
    if (numMsg <= 0 || msg == nullptr || response == nullptr || appdataPtr == nullptr) {
      return PAM_CONV_ERR;
    }

    auto* data = static_cast<PamConversationData*>(appdataPtr);
    auto* replies = static_cast<pam_response*>(std::calloc(static_cast<std::size_t>(numMsg), sizeof(pam_response)));
    if (replies == nullptr) {
      return PAM_BUF_ERR;
    }

    for (int i = 0; i < numMsg; ++i) {
      if (msg[i] == nullptr) {
        for (int j = 0; j < i; ++j) {
          if (replies[j].resp != nullptr) {
            ::explicit_bzero(replies[j].resp, std::strlen(replies[j].resp));
            std::free(replies[j].resp);
          }
        }
        std::free(replies);
        return PAM_CONV_ERR;
      }

      switch (msg[i]->msg_style) {
      case PAM_PROMPT_ECHO_OFF:
        if (data != nullptr && !data->passwordConsumed && data->password != nullptr) {
          replies[i].resp = ::strdup(data->password);
          data->passwordConsumed = true;
        } else {
          replies[i].resp = ::strdup("");
        }
        break;
      case PAM_PROMPT_ECHO_ON:
        replies[i].resp = ::strdup("");
        break;
      case PAM_ERROR_MSG:
      case PAM_TEXT_INFO:
        replies[i].resp = nullptr;
        break;
      default:
        for (int j = 0; j <= i; ++j) {
          if (replies[j].resp != nullptr) {
            ::explicit_bzero(replies[j].resp, std::strlen(replies[j].resp));
            std::free(replies[j].resp);
          }
        }
        std::free(replies);
        return PAM_CONV_ERR;
      }

      if ((msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
          && replies[i].resp == nullptr) {
        for (int j = 0; j <= i; ++j) {
          if (replies[j].resp != nullptr) {
            ::explicit_bzero(replies[j].resp, std::strlen(replies[j].resp));
            std::free(replies[j].resp);
          }
        }
        std::free(replies);
        return PAM_BUF_ERR;
      }
    }

    *response = replies;
    return PAM_SUCCESS;
  }

  [[nodiscard]] bool writeAll(int fd, const void* data, std::size_t len) {
    auto* bytes = static_cast<const std::uint8_t*>(data);
    std::size_t remaining = len;
    while (remaining > 0) {
      const ssize_t n = ::write(fd, bytes, remaining);
      if (n > 0) {
        bytes += static_cast<std::size_t>(n);
        remaining -= static_cast<std::size_t>(n);
      } else if (n < 0 && errno == EINTR) {
        continue;
      } else {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] bool readAll(int fd, void* data, std::size_t len) {
    auto* bytes = static_cast<std::uint8_t*>(data);
    std::size_t remaining = len;
    while (remaining > 0) {
      const ssize_t n = ::read(fd, bytes, remaining);
      if (n > 0) {
        bytes += static_cast<std::size_t>(n);
        remaining -= static_cast<std::size_t>(n);
      } else if (n < 0 && errno == EINTR) {
        continue;
      } else {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] bool writeResult(int fd, const PamAuthenticator::Result& result) {
    const std::uint8_t success = result.success ? 1 : 0;
    if (!writeAll(fd, &success, sizeof(success))) {
      return false;
    }
    const std::uint32_t len = static_cast<std::uint32_t>(std::min(result.message.size(), kMaxPamMessageBytes));
    if (!writeAll(fd, &len, sizeof(len))) {
      return false;
    }
    if (len > 0 && !writeAll(fd, result.message.data(), len)) {
      return false;
    }
    return true;
  }

  [[nodiscard]] bool readResult(int fd, PamAuthenticator::Result& result) {
    std::uint8_t success = 0;
    if (!readAll(fd, &success, sizeof(success))) {
      return false;
    }
    std::uint32_t len = 0;
    if (!readAll(fd, &len, sizeof(len))) {
      return false;
    }
    if (len > kMaxPamMessageBytes) {
      return false;
    }
    result.success = success != 0;
    result.message.clear();
    if (len > 0) {
      result.message.resize(len);
      if (!readAll(fd, result.message.data(), len)) {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] PamAuthenticator::Result authenticateDirect(std::string_view password, std::string_view service) {
    std::string user = PamAuthenticator::currentUsername();
    if (user.empty()) {
      return PamAuthenticator::Result{.success = false, .message = i18n::tr("auth.pam.user-unavailable")};
    }
    if (service.empty()) {
      service = "login";
    }

    std::string passwordCopy(password);
    PamConversationData convData{.password = passwordCopy.c_str(), .passwordConsumed = false};
    pam_conv conv = {
        .conv = &pamConversation,
        .appdata_ptr = &convData,
    };

    PamHandle pamh;
    const int startRc = pam_start(service.data(), user.c_str(), &conv, &pamh.h);
    if (startRc != PAM_SUCCESS || pamh.h == nullptr) {
      secureClear(passwordCopy);
      return PamAuthenticator::Result{.success = false, .message = i18n::tr("auth.pam.start-failed")};
    }

    int rc = pam_authenticate(pamh.h, 0);
    if (rc == PAM_SUCCESS) {
      // An unprivileged locker can't read /etc/shadow for the account stack, so
      // ignore PAM_AUTHINFO_UNAVAIL; pam_authenticate already proved identity.
      const int acctRc = pam_acct_mgmt(pamh.h, 0);
      if (acctRc != PAM_SUCCESS && acctRc != PAM_AUTHINFO_UNAVAIL) {
        rc = acctRc;
      }
    }
    const char* err = pam_strerror(pamh.h, rc);
    const std::string errStr = err != nullptr ? err : i18n::tr("auth.pam.authentication-failed");
    pamh.lastRc = rc;

    secureClear(passwordCopy);

    if (rc == PAM_SUCCESS) {
      return PamAuthenticator::Result{.success = true, .message = {}};
    }

    return PamAuthenticator::Result{.success = false, .message = errStr};
  }

  [[nodiscard]] std::string convertCyrillicToLatinQwerty(std::string_view input) {
    std::string result;
    result.reserve(input.size());
    bool hasConverted = false;

    std::size_t i = 0;
    while (i < input.size()) {
      const auto b0 = static_cast<unsigned char>(input[i]);
      if (b0 < 0x80) {
        result.push_back(static_cast<char>(b0));
        ++i;
      } else if (b0 >= 0xC2 && (b0 & 0xE0) == 0xC0 && i + 1 < input.size()) {
        const auto b1 = static_cast<unsigned char>(input[i + 1]);
        if ((b1 & 0xC0) != 0x80) {
          result.push_back(static_cast<char>(b0));
          ++i;
          continue;
        }
        const std::uint32_t cp = ((b0 & 0x1F) << 6) | (b1 & 0x3F);
        i += 2;
        char mapped = '\0';
        switch (cp) {
        case 0x0430: mapped = 'f'; break; // а
        case 0x0431: mapped = ','; break; // б
        case 0x0432: mapped = 'd'; break; // в
        case 0x0433: mapped = 'u'; break; // г
        case 0x0434: mapped = 'l'; break; // д
        case 0x0435: mapped = 't'; break; // е
        case 0x0451: mapped = '`'; break; // ё
        case 0x0436: mapped = ';'; break; // ж
        case 0x0437: mapped = 'p'; break; // з
        case 0x0438: mapped = 'b'; break; // и
        case 0x0439: mapped = 'q'; break; // й
        case 0x043A: mapped = 'r'; break; // к
        case 0x043B: mapped = 'k'; break; // л
        case 0x043C: mapped = 'v'; break; // м
        case 0x043D: mapped = 'y'; break; // н
        case 0x043E: mapped = 'j'; break; // о
        case 0x043F: mapped = 'g'; break; // п
        case 0x0440: mapped = 'h'; break; // р
        case 0x0441: mapped = 'c'; break; // с
        case 0x0442: mapped = 'n'; break; // т
        case 0x0443: mapped = 'e'; break; // у
        case 0x0444: mapped = 'a'; break; // ф
        case 0x0445: mapped = '['; break; // х
        case 0x0446: mapped = 'w'; break; // ц
        case 0x0447: mapped = 'x'; break; // ч
        case 0x0448: mapped = 'i'; break; // ш
        case 0x0449: mapped = 'o'; break; // щ
        case 0x044A: mapped = ']'; break; // ъ
        case 0x044B: mapped = 's'; break; // ы
        case 0x044C: mapped = 'm'; break; // ь
        case 0x044D: mapped = '\''; break; // э
        case 0x044E: mapped = '.'; break; // ю
        case 0x044F: mapped = 'z'; break; // я
        case 0x0410: mapped = 'F'; break; // А
        case 0x0411: mapped = '<'; break; // Б
        case 0x0412: mapped = 'D'; break; // В
        case 0x0413: mapped = 'U'; break; // Г
        case 0x0414: mapped = 'L'; break; // Д
        case 0x0415: mapped = 'T'; break; // Е
        case 0x0401: mapped = '~'; break; // Ё
        case 0x0416: mapped = ':'; break; // Ж
        case 0x0417: mapped = 'P'; break; // З
        case 0x0418: mapped = 'B'; break; // И
        case 0x0419: mapped = 'Q'; break; // Й
        case 0x041A: mapped = 'R'; break; // К
        case 0x041B: mapped = 'K'; break; // Л
        case 0x041C: mapped = 'V'; break; // М
        case 0x041D: mapped = 'Y'; break; // Н
        case 0x041E: mapped = 'J'; break; // О
        case 0x041F: mapped = 'G'; break; // П
        case 0x0420: mapped = 'H'; break; // Р
        case 0x0421: mapped = 'C'; break; // С
        case 0x0422: mapped = 'N'; break; // Т
        case 0x0423: mapped = 'E'; break; // У
        case 0x0424: mapped = 'A'; break; // Ф
        case 0x0425: mapped = '{'; break; // Х
        case 0x0426: mapped = 'W'; break; // Ц
        case 0x0427: mapped = 'X'; break; // Ч
        case 0x0428: mapped = 'I'; break; // Ш
        case 0x0429: mapped = 'O'; break; // Щ
        case 0x042A: mapped = '}'; break; // Ъ
        case 0x042B: mapped = 'S'; break; // Ы
        case 0x042C: mapped = 'M'; break; // Ь
        case 0x042D: mapped = '"'; break; // Э
        case 0x042E: mapped = '>'; break; // Ю
        case 0x042F: mapped = 'Z'; break; // Я
        case 0x0456: mapped = 's'; break; // і
        case 0x0406: mapped = 'S'; break; // І
        case 0x0457: mapped = ']'; break; // ї
        case 0x0407: mapped = '}'; break; // Ї
        case 0x0454: mapped = '\''; break; // є
        case 0x0404: mapped = '"'; break; // Є
        case 0x0491: mapped = 'u'; break; // ґ
        case 0x0490: mapped = 'U'; break; // Ґ
        case 0x045E: mapped = 'u'; break; // ў
        case 0x040E: mapped = 'U'; break; // Ў
        default: break;
        }
        if (mapped != '\0') {
          result.push_back(mapped);
          hasConverted = true;
        } else {
          result.push_back(static_cast<char>(b0));
          result.push_back(static_cast<char>(b1));
        }
      } else if (b0 == 0xE2 && i + 2 < input.size()
                 && static_cast<unsigned char>(input[i + 1]) == 0x84
                 && static_cast<unsigned char>(input[i + 2]) == 0x96) {
        // № (U+2116) -> '#'
        result.push_back('#');
        hasConverted = true;
        i += 3;
      } else {
        result.push_back(static_cast<char>(b0));
        ++i;
      }
    }

    if (!hasConverted) {
      secureClear(result);
      return {};
    }
    return result;
  }

  [[nodiscard]] PamAuthenticator::Result runPamAuthInChild(std::string_view password, std::string_view service) {
    int pipeFds[2] = {-1, -1};
    if (::pipe2(pipeFds, O_CLOEXEC) != 0) {
      return PamAuthenticator::Result{.success = false, .message = i18n::tr("auth.pam.start-failed")};
    }

    std::string passwordCopy(password);
    std::string serviceCopy(service.empty() ? "login" : std::string(service));

    const pid_t pid = ::fork();
    if (pid < 0) {
      secureClear(passwordCopy);
      ::close(pipeFds[0]);
      ::close(pipeFds[1]);
      return PamAuthenticator::Result{.success = false, .message = i18n::tr("auth.pam.start-failed")};
    }

    if (pid == 0) {
      ::close(pipeFds[0]);
      // Avoid calling kLog in child to prevent deadlocks on gLogMutex after fork.
      const PamAuthenticator::Result result = authenticateDirect(passwordCopy, serviceCopy);
      secureClear(passwordCopy);
      if (!writeResult(pipeFds[1], result)) {
        ::close(pipeFds[1]);
        ::_exit(128);
      }
      ::close(pipeFds[1]);
      ::_exit(result.success ? 0 : 1);
    }

    secureClear(passwordCopy);
    ::close(pipeFds[1]);

    pollfd pfd{.fd = pipeFds[0], .events = POLLIN, .revents = 0};
    const int pollRc = ::poll(&pfd, 1, 10000);

    PamAuthenticator::Result result;
    bool readOk = false;
    if (pollRc > 0 && (pfd.revents & (POLLIN | POLLHUP)) != 0) {
      readOk = readResult(pipeFds[0], result);
    } else if (pollRc == 0) {
      ::kill(pid, SIGKILL);
    }
    ::close(pipeFds[0]);

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }

    if (!readOk || !WIFEXITED(status) || WEXITSTATUS(status) >= 128) {
      return PamAuthenticator::Result{.success = false, .message = i18n::tr("auth.pam.start-failed")};
    }

    return result;
  }

} // namespace

PamAuthenticator::Result
PamAuthenticator::authenticateCurrentUser(std::string_view password, std::string_view service) const {
  std::string qwerty = convertCyrillicToLatinQwerty(password);
  if (!qwerty.empty() && qwerty != password) {
    const Result fallbackResult = runPamAuthInChild(qwerty, service);
    secureClear(qwerty);
    if (fallbackResult.success) {
      kLog.debug("pam authentication succeeded via layout transliteration fallback");
      return fallbackResult;
    }
  } else {
    secureClear(qwerty);
  }

  const Result directResult = runPamAuthInChild(password, service);
  if (directResult.success) {
    kLog.debug("pam authentication succeeded directly");
  } else {
    kLog.debug("pam authentication failed");
  }
  return directResult;
}

std::string PamAuthenticator::currentUsername() {
  const uid_t uid = getuid();
  passwd pwd{};
  passwd* result = nullptr;
  std::vector<char> buf(4096);

  while (true) {
    const int rc = getpwuid_r(uid, &pwd, buf.data(), buf.size(), &result);
    if (rc == 0 && result != nullptr) {
      return std::string(result->pw_name != nullptr ? result->pw_name : "");
    }
    if (rc != ERANGE) {
      return {};
    }
    buf.resize(buf.size() * 2);
    if (buf.size() > 1 << 20) {
      return {};
    }
  }
}
