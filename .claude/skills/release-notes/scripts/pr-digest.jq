# Reduce a single `gh pr view` JSON object to a compact markdown record with
# YAML frontmatter. Bot dependency PRs keep only their title; human PRs keep a
# bounded slice of the body. Expects: --argjson limit <int>.
(.author.is_bot == true
  or (.author.login | ascii_downcase | test("renovate|dependabot|\\[bot\\]"))) as $bot
| (.labels // [] | map(.name) | join(", ")) as $labels
| "---",
  "pr: \(.number)",
  "title: \(.title | @json)",
  "url: \(.url)",
  "author: \(.author.login)",
  "bot: \($bot)",
  "labels: \($labels | @json)",
  "---",
  "",
  (if $bot then
     "(dependency update — body omitted, title is sufficient)"
   else
     (.body // "" | .[0:$limit])
   end)
