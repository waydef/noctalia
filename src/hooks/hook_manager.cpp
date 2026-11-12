#include "hooks/hook_manager.h"

#include "core/log.h"

#include <string_view>

namespace {

  constexpr Logger kLog("hooks");

  bool isShellName(std::string_view name) {
    if (name.empty() || (name.front() >= '0' && name.front() <= '9')) {
      return false;
    }
    for (const char c : name) {
      const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
      if (!ok) {
        return false;
      }
    }
    return true;
  }

  // 'value' for /bin/sh, with every ' written as '\''
  std::string shellQuote(std::string_view value) {
    std::string out = "'";
    for (const char c : value) {
      if (c == '\'') {
        out += "'\\''";
      } else {
        out += c;
      }
    }
    out += '\'';
    return out;
  }

} // namespace

void HookManager::setCommandRunner(CommandRunner runner) { m_runner = std::move(runner); }

void HookManager::setBlockingCommandRunner(CommandRunner runner) { m_blockingRunner = std::move(runner); }

void HookManager::reload(const HooksConfig& config) { m_config = config; }

void HookManager::fire(HookKind kind) const { (void)fireWithRunner(kind, m_runner); }

bool HookManager::fireBlocking(HookKind kind) const {
  return fireWithRunner(kind, m_blockingRunner ? m_blockingRunner : m_runner);
}

bool HookManager::fireWithRunner(HookKind kind, const CommandRunner& runner, std::string_view envPrefix) const {
  if (kind == HookKind::Count || !runner) {
    return false;
  }
  const auto& cmds = m_config.commands[static_cast<std::size_t>(kind)];
  if (cmds.empty()) {
    return true;
  }
  const std::string_view name = hookKindKey(kind);
  kLog.debug("hook '{}' running {} command(s)", name, cmds.size());
  bool ok = true;
  for (const auto& cmd : cmds) {
    if (!runner(envPrefix.empty() ? cmd : std::string(envPrefix) + cmd)) {
      kLog.warn("hook '{}' command failed: {}", name, cmd);
      ok = false;
    }
  }
  return ok;
}

void HookManager::fire(HookKind kind, std::initializer_list<EnvVar> env) const {
  fireWithEnv(kind, std::span<const EnvVar>(env.begin(), env.size()));
}

void HookManager::fire(HookKind kind, const std::vector<EnvVar>& env) const { fireWithEnv(kind, env); }

// The variables go into the command line as "export NAME='value';" for the /bin/sh -lc runner.
// setenv/unsetenv on the whole process raced with other threads reading environ (getenv in
// localtime, curl, image decoders) and could crash the shell.
void HookManager::fireWithEnv(HookKind kind, std::span<const EnvVar> env) const {
  std::string prefix;
  for (const auto& [key, value] : env) {
    if (key == nullptr || !isShellName(key)) {
      kLog.warn("hook '{}': skipped env var with an invalid name", hookKindKey(kind));
      continue;
    }
    prefix += "export ";
    prefix += key;
    prefix += '=';
    prefix += shellQuote(value);
    prefix += "; ";
  }
  (void)fireWithRunner(kind, m_runner, prefix);
}
