#include "hooks/hook_manager.h"
#include "tests/test_check.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

std::string_view hookKindKey(HookKind kind) {
  if (kind == HookKind::WallpaperChanged) {
    return "wallpaper_changed";
  }
  return "unknown";
}

namespace {

  // runs the command through /bin/sh -c, as the shell runner does, and returns its stdout
  std::string runShell(const std::string& command) {
    std::string quoted = "'";
    for (const char c : command) {
      quoted += c == '\'' ? std::string("'\\''") : std::string(1, c);
    }
    quoted += "'";
    std::string out;
    if (FILE* pipe = ::popen(("/bin/sh -c " + quoted).c_str(), "r")) {
      char buf[256];
      while (std::fgets(buf, sizeof(buf), pipe) != nullptr) {
        out += buf;
      }
      ::pclose(pipe);
    }
    return out;
  }

} // namespace

int main() {
  constexpr const char* kPathName = "NOCTALIA_WALLPAPER_PATH";
  constexpr const char* kConnectorName = "NOCTALIA_WALLPAPER_CONNECTOR";

  ::unsetenv(kPathName);
  ::unsetenv(kConnectorName);

  HookManager hooks;
  HooksConfig config;
  config.commands[static_cast<std::size_t>(HookKind::WallpaperChanged)] = {
      "printf '%s|%s' \"$NOCTALIA_WALLPAPER_PATH\" \"$NOCTALIA_WALLPAPER_CONNECTOR\""};
  hooks.reload(config);

  std::vector<std::string> commands;
  bool envTouched = false;
  hooks.setCommandRunner([&](const std::string& command) {
    commands.push_back(command);
    // the process environment stays as it was: other threads read it while hooks fire
    envTouched = envTouched || std::getenv(kPathName) != nullptr || std::getenv(kConnectorName) != nullptr;
    return true;
  });

  const std::string path = "/tmp/noctalia test/it's $HOME `x`.png";
  hooks.fire(HookKind::WallpaperChanged, {{kPathName, path}, {kConnectorName, "DP-1"}});

  TEST_CHECK(commands.size() == 1);
  TEST_CHECK(!envTouched);
  TEST_CHECK(commands[0].starts_with("export NOCTALIA_WALLPAPER_PATH="));
  TEST_CHECK(commands[0].ends_with(config.commands[static_cast<std::size_t>(HookKind::WallpaperChanged)][0]));
  TEST_CHECK(runShell(commands[0]) == path + "|DP-1");
  TEST_CHECK(std::getenv(kPathName) == nullptr);
  TEST_CHECK(std::getenv(kConnectorName) == nullptr);

  // a name the shell cannot take is dropped, the hook still runs
  commands.clear();
  hooks.fire(HookKind::WallpaperChanged, {{"BAD-NAME", "x"}});
  TEST_CHECK(commands.size() == 1);
  TEST_CHECK(commands[0].find("BAD-NAME") == std::string::npos);

  return 0;
}
