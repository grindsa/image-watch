# Parse an env file without shell expansion.
# Matching double quotes are removed. Single quotes are kept.
# Existing non-empty variables are left alone.

load_env_file() {
  local file="$1"
  [ -f "$file" ] || return 0

  local line key value
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue
    case "$line" in
      \#*) continue ;;
      export\ *) line="${line#export }" ;;
    esac
    case "$line" in
      *=*) ;;
      *) continue ;;
    esac

    key="${line%%=*}"
    value="${line#*=}"
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"

    case "$key" in
      ""|*[!A-Za-z0-9_]*|[0-9]*) continue ;;
    esac
    case "$value" in
      \"*\") value="${value:1:${#value}-2}" ;;
    esac

    if [ -z "${!key+x}" ] || [ -z "${!key}" ]; then
      printf -v "$key" '%s' "$value"
      export "$key"
    fi
  done < "$file"
}
