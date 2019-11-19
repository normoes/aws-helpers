#/usr/bin/env bash
_aws-ssm-pstore_completions()
{
  if [ "${#COMP_WORDS[@]}" == "2" ]; then
    COMPREPLY=($(compgen -W "$(cat ~/.aws/config | grep '^\[' | tr -d '[]' | cut -d ' ' -f 2)" -- "${COMP_WORDS[1]}"))
    # COMPREPLY+=($(compgen -A alias "${COMP_WORDS[1]}" | grep -i aws-vault))
  fi
  # if [ "${#COMP_WORDS[@]}" != "3" ]; then
  #   return
  # fi
  if [ "${#COMP_WORDS[@]}" == "3" ]; then
    # on directory completion add "/" instead of whitespace
    compopt -o filenames
    COMPREPLY=($(compgen -o filenames -A directory "${COMP_WORDS[2]}"))
  fi
  # stop here, do not add anything when pressing <TAB>
  if [ "${#COMP_WORDS[@]}" != "4" ]; then
    return
  fi
}
complete -F _aws-ssm-pstore_completions aws-ssm-pstore
