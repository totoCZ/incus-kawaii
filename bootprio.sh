incus list --format json | jq -r '
  map(. + {priority: (.config["boot.autostart.priority"] // "0" | tonumber)})

  | sort_by(.priority) | reverse
  | ["NAME", "AUTOSTART", "PRIORITY"], (.[] | [.name, .config["boot.autostart"], .priority])
  | @tsv' | column -t -s $'\t'
