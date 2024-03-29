#!/usr/bin/env bash

__snyk_previous_extglob_setting=$(shopt -p extglob)
shopt -s extglob

function __snyk_debug_print
{
    [[ -n $_SNYK_COMPLETE_DEBUG ]] && echo "$@" >> ZZZ
}

__snyk_to_extglob() {
	local extglob=$( __snyk_to_alternatives "$1" )
	echo "@($extglob)"
}

__snyk_to_alternatives() {
	local parts=( $1 )
	local IFS='|'
	echo "${parts[*]}"
}


__snyk_pos_first_nonflag() {
	local argument_flags=$1

	local counter=$((${subcommand_pos:-${command_pos}} + 1))
	while [ "$counter" -le "$cword" ]; do
		if [ -n "$argument_flags" ] && eval "case '${words[$counter]}' in $argument_flags) true ;; *) false ;; esac"; then
			(( counter++ ))
			# eat "=" in case of --option=arg syntax
			[ "${words[$counter]}" = "=" ] && (( counter++ ))
		else
			case "${words[$counter]}" in
				-*)
					;;
				*)
					break
					;;
			esac
		fi

		# Bash splits words at "=", retaining "=" as a word, examples:
		# "--debug=false" => 3 words, "--log-opt syslog-facility=daemon" => 4 words
		while [ "${words[$counter + 1]}" = "=" ] ; do
			counter=$(( counter + 2))
		done

		(( counter++ ))
	done

	echo "$counter"
}

__snyk_subcommands() {
    
	local subcommands="$1"

	local counter=$((command_pos + 1))
	while [ "$counter" -lt "$cword" ]; do
		case "${words[$counter]}" in
			$(__snyk_to_extglob "$subcommands") )
				subcommand_pos=$counter
				local subcommand=${words[$counter]}
				local completions_func=_snyk_${command}_${subcommand//-/_}
				declare -F "$completions_func" >/dev/null && "$completions_func"
				return 0
				;;
		esac
		(( counter++ ))
	done

	return 1
}

###############################################################################
## Snyk utilities
###############################################################################

_snyk_snyk() {
	# global options that may appear after the snyk command
	local boolean_options="
		$global_boolean_options
		--help
		--version -v
		--about
	"

	case "$prev" in
		--config)
			_filedir -d
			return
			;;
		--context|-c)
			__snyk_complete_contexts
			return
			;;
		--log-level|-l)
			__snyk_complete_log_levels
			return
			;;
		$(__snyk_to_extglob "$global_options_with_args") )
			return
			;;
	esac

	case "$cur" in
		-*)
			COMPREPLY=( $( compgen -W "$boolean_options $global_options_with_args" -- "$cur" ) )
			;;
		*)
			local counter=$( __snyk_pos_first_nonflag "$(__snyk_to_extglob "$global_options_with_args")" )
			if [ "$cword" -eq "$counter" ]; then
				COMPREPLY=( $( compgen -W "${commands[*]} help" -- "$cur" ) )
			fi
			;;
	esac
}

__snyk_complete_docker_images()
{
    COMPREPLY=( $(compgen -W "$(__snyk_get_docker_images)" -- "$cur") )
}

__snyk_get_docker_images()
{
    local docker_images=""
    if  $(command -v docker &> /dev/null)
    then
	docker_images=$(docker images --format "{{.Repository}}")
    fi
    echo "$docker_images"
}

__snyk_complete_environment()
{
    COMPREPLY=( $(compgen -W 'backend distributed external frontend hosted internal mobile onprem saas' -- "$cur") )
}

__snyk_complete_true_false()
{
    COMPREPLY=( $(compgen -W 'true false' -- "$cur") )
}

# Right now this is only used by sbom verb, if something else uses it then split it off
#
__snyk_complete_package_manager()
{
    COMPREPLY=( $(compgen -W 'pip' -- "$cur") )
}

__snyk_complete_vulnerable_paths()
{
    COMPREPLY=( $(compgen -W 'none some all' -- "$cur") )
}

__snyk_complete_sbom_format()
{
    COMPREPLY=( $(compgen -W 'cyclonedx1.4+json cyclonedx1.4+xml spdx2.3+json' -- "$cur") )
}

__snyk_complete_severity_threshold()
{
    COMPREPLY=( $(compgen -W 'low medium high critical' -- "$cur") )
}

__snyk_complete_fail_on()
{
    COMPREPLY=( $(compgen -W 'all upgradable patchable' -- "$cur") )
}

__snyk_complete_lifecycle()
{
    COMPREPLY=( $(compgen -W 'development production sandbox' -- "$cur") )
}

###############################################################################
## Snyk auth
###############################################################################
_snyk_auth() 
{
	local boolean_options="
        -d
	"

	local all_options="$boolean_options"

    __snyk_debug_print "prev: [$prev] cur: [$cur] reply [$COMPREPLY]"

    case "$cur" in
        -*)
            COMPREPLY=( $( compgen -W "$all_options" -- "$cur" ) )
            ;;
    esac
}    

###############################################################################
## snyk code
###############################################################################
_snyk_code()
{
	local subcommands="
		test
        "
	__snyk_subcommands "$subcommands $aliases" && return

	COMPREPLY=( $( compgen -W "$subcommands" -- "$cur" ) )
}

_snyk_code_test()
{
    # This is used to get around the mac bash/nospace issue when using --flag-with-value= type params
    #
    local rvalMode=""

	local options_with_args="
        --fail-on=
        --json-file-output=
        --org=
        --severity-threshold=
	"

	local boolean_options="
        --json
        --sarif
	"

	local all_options="$options_with_args $boolean_options"

    # On macs with old bash (like mine) the nospace option doesn't work, so have to
    # contend with the vars with args. If the current arg ends with an `=` then override
    # 
    if [[ "$cur" == *= ]]
    then
        rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev=$cur
	    cur=""
	else
	    cur=""
	fi
    elif [[ "$cur" == *=* ]]
    then
	rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev="${cur%=*}="
	    cur=${cur#*=}
	else
	    cur=""
	fi
    fi

    # if prev is an = then we are trying to find an rval. Loop back through the
    # comp words to find which one and override
    #
    if [[ "$prev" == "=" ]]
    then
	for (( word=${#COMP_WORDS[@]}-1 ; word>=0 ; word-- ))
	do
	    [[ "${COMP_WORDS[word]}" == --* ]] && prev="${COMP_WORDS[word]}"
	done
    fi

    __snyk_debug_print "prev: [$prev] cur: [$cur] reply [$COMPREPLY]"

    case "$prev" in
        --fail-on=|--fail-on)
            __snyk_complete_fail_on
            return
            ;;
        --json-file-output=|--json-file-output)
            _filedir '@(json)'
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --org=|--org)
            return
            ;;
        --severity-threshold=|--severity-threshold)
            __snyk_complete_severity_threshold
            return
            ;;
    esac
    
    
    if [[ -z $rvalMode ]]
    then        
        case "$cur" in
            -*)
                COMPREPLY=( $( compgen -W "$all_options" -- "$cur" ) )
                ;;
        esac
    fi
    
}

###############################################################################
## Snyk Config
###############################################################################
_snyk_config() {
	local subcommands="
        clear
        get
        set
        unset
	"
	local aliases="
	"
	__snyk_subcommands "$subcommands $aliases" && return

	case "$cur" in
		-*)
			COMPREPLY=( $( compgen -W "--help" -- "$cur" ) )
			;;
		*)
			COMPREPLY=( $( compgen -W "$subcommands" -- "$cur" ) )
			;;
	esac
}

_snyk_config_completer() {
	local subcommands="
		api
        disable-analytics
        endpoint
        oci-registry-url
        oci-registry-username
        oci-registry-password
        "
        
	__snyk_subcommands "$subcommands" && return

	COMPREPLY=( $( compgen -W "$subcommands" -- "$cur" ) )
}

_snyk_config_clear() {
    _snyk_config_completer
}

_snyk_config_get() {
    _snyk_config_completer
}

_snyk_config_set() {
    _snyk_config_completer
}

_snyk_config_unset() {
    _snyk_config_completer
}

###############################################################################
## Snyk SBOM
###############################################################################
_snyk_sbom() {
    # This is used to get around the mac bash/nospace issue when using --flag-with-value= type params
    #
    local rvalMode=""

    # For args that are global or appear in more than one flavor
    #
    local options_with_args="
        --detection-depth=
        --exclude=
        --file=
        --format=
        --max-depth=
        --org=
        --package-manager=
        --skip-unresolved=
        --strict-out-of-sync=
        --version=
	"

    local options_with_args_gradle="
        --configuration-attributes=
        --configuration-matching=
        --sub-project=
        --init-script=
	"


    local boolean_options="
        --all-projects
        --dev
        --prune-repeated-subdependencies
        --unmanaged
	"
	
    local boolean_options_maven="
        --maven-aggregate-project
        --scan-all-unmanaged
        --scan-unmanaged
    "    
    
    local boolean_options_gradle="
        --all-projects
        --all-sub-projects
    "    
    # I don't know if the --packages-folder is really not "--packages-folder="
    #
    local boolean_options_nuget="
        --assets-project-name
        --packages-folder
    "    

    local boolean_options_yarn="
        --yarn-workspaces
    "    

    local all_options="
        $options_with_args
        $options_with_args_gradle
        $boolean_options
        $boolean_options_maven
        $boolean_options_gradle
        $boolean_options_nuget
        $boolean_options_yarn
    "
    


    # On macs with old bash (like mine) the nospace option doesn't work, so have to
    # contend with the vars with args. If the current arg ends with an `=` then override
    # 
    if [[ "$cur" == *= ]]
    then
        rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev=$cur
	    cur=""
	else
	    cur=""
	fi
    elif [[ "$cur" == *=* ]]
    then
	rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev="${cur%=*}="
	    cur=${cur#*=}
	else
	    cur=""
	fi
    fi

    # if prev is an = then we are trying to find an rval. Loop back through the
    # comp words to find which one and override
    #
    if [[ "$prev" == "=" ]]
    then
	for (( word=${#COMP_WORDS[@]}-1 ; word>=0 ; word-- ))
	do
	    [[ "${COMP_WORDS[word]}" == --* ]] && prev="${COMP_WORDS[word]}"
	done
    fi
    
    __snyk_debug_print "prev: [$prev] cur: [$cur] reply [$COMPREPLY]"

    case "$prev" in
        --exclude=|--exclude)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --file=|--file)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --format=|--format)
            __snyk_complete_sbom_format
            return
            ;;
        --init-script=|--init-script)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --org=|--org)
            return
            ;;
        --package-manager=|--package-manager)
            __snyk_complete_package_manager
            return
            ;;
        --strict-out-of-sync=|--strict-out-of-sync)
            __snyk_complete_true_false
            return
            ;;
    esac
   
    if [[ -z $rvalMode ]]
    then        
        case "$cur" in
            -*)
                COMPREPLY=( $( compgen -W "$all_options" -- "$cur" ) )
                ;;
        esac
    fi
}
###############################################################################
## Snyk Container
###############################################################################

_snyk_container_sbom() {
    # This is used to get around the mac bash/nospace issue when using --flag-with-value= type params
    #
    local rvalMode=""

    local options_with_args="
        --format=
        --org=
	"

    local boolean_options="
        --exclude-app-vulns
	"
	
    local all_options="$options_with_args $boolean_options"

    # On macs with old bash (like mine) the nospace option doesn't work, so have to
    # contend with the vars with args. If the current arg ends with an `=` then override
    # 
    if [[ "$cur" == *= ]]
    then
        rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev=$cur
	    cur=""
	else
	    cur=""
	fi
    elif [[ "$cur" == *=* ]]
    then
	rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev="${cur%=*}="
	    cur=${cur#*=}
	else
	    cur=""
	fi
    fi

    # if prev is an = then we are trying to find an rval. Loop back through the
    # comp words to find which one and override
    #
    if [[ "$prev" == "=" ]]
    then
	for (( word=${#COMP_WORDS[@]}-1 ; word>=0 ; word-- ))
	do
	    [[ "${COMP_WORDS[word]}" == --* ]] && prev="${COMP_WORDS[word]}"
	done
    fi
    
    __snyk_debug_print "prev: [$prev] cur: [$cur] reply [$COMPREPLY]"

    case "$prev" in
        --exclude=|--exclude)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --file=|--file)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --format=|--format)
            __snyk_complete_sbom_format
            return
            ;;
        --org=|--org)
            return
            ;;
    esac

    if [[ -z $rvalMode ]]
    then        
        case "$cur" in
            -*)
                COMPREPLY=( $( compgen -W "$all_options" -- "$cur" ) )
                ;;
	    *)
    		__snyk_complete_docker_images
		;;
        esac
    fi

    
}

_snyk_container_monitor() {
    _snyk_container_monitor_and_test
}

_snyk_container_test() {
    _snyk_container_monitor_and_test
}

_snyk_container_monitor_and_test() {
    # This is used to get around the mac bash/nospace issue when using --flag-with-value= type params
    #
    local rvalMode=""

    local options_with_args="
        --fail-on=
        --file=
        --json-file-output=
        --org=
        --password=
        --platform=
        --policy-path=
        --project-business-criticality=
        --project-environment=
        --project-lifecycle=
        --project-name=
        --project-tags=
        --sarif-file-output=
        --severity-threshold=
        --tags=
        --username=
	"

    local boolean_options="
        --app-vulns
        --exclude-base-image-vulns
        --exclude-app-vulns
        --json
        --nested-jars-depth
        --print-deps
        --sarif
	"
	
    local all_options="$options_with_args $boolean_options"

    # On macs with old bash (like mine) the nospace option doesn't work, so have to
    # contend with the vars with args. If the current arg ends with an `=` then override
    # 
    if [[ "$cur" == *= ]]
    then
        rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev=$cur
	    cur=""
	else
	    cur=""
	fi
    elif [[ "$cur" == *=* ]]
    then
	rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev="${cur%=*}="
	    cur=${cur#*=}
	else
	    cur=""
	fi
    fi

    # if prev is an = then we are trying to find an rval. Loop back through the
    # comp words to find which one and override
    #
    if [[ "$prev" == "=" ]]
    then
	for (( word=${#COMP_WORDS[@]}-1 ; word>=0 ; word-- ))
	do
	    [[ "${COMP_WORDS[word]}" == --* ]] && prev="${COMP_WORDS[word]}"
	done
    fi
    
    __snyk_debug_print "prev: [$prev] cur: [$cur] reply [$COMPREPLY]"

    case "$prev" in
        --fail-on=|--fail-on)
            __snyk_complete_fail_on
            return
            ;;
        --file=|--file)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --json-file-output=|--json-file-output)
            _filedir '@(json)'
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --org=|--org)
            return
            ;;
        --password=|--password)
            return
            ;;
        --platform=|--platform)
            COMPREPLY=( $(compgen -W 'linux/amd64 linux/arm64 linux/riscv64 linux/ppc64le linux/s390x linux/386 linux/arm/v7 linux/arm/v6' -- "$cur") )                        
            return
            ;;
        --policy-path=|--policy-path)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --project-business-criticality=|--project-business-criticality)
            __snyk_complete_severity_threshold
            return
            ;;
        --project-environment=|--project-environment)
            __snyk_complete_environment
            return
            ;;
        --project-lifecycle=|--project-lifecycle)
            __snyk_complete_lifecycle
            return
            ;;
        --project-name=|--project-name)
            return
            ;;
        --project-tags=|--tags=|--project-tags=|--tags)
            return
            ;;
        --sarif-file-output=|--sarif-file-output)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --severity-threshold=|--severity-threshold)
            __snyk_complete_severity_threshold
            return
            ;;
        --username=|--username)
            return
            ;;
    esac
    

   
    if [[ -z $rvalMode ]]
    then        
        case "$cur" in
            -*)
                COMPREPLY=( $( compgen -W "$all_options" -- "$cur" ) )
                ;;
	    *)
		__snyk_complete_docker_images
		;;
        esac
    fi
}

_snyk_container() {
	local subcommands="
		monitor
        test
        sbom
	"
	local aliases="
	"
	__snyk_subcommands "$subcommands $aliases" && return

	case "$cur" in
		-*)
			COMPREPLY=( $( compgen -W "--help" -- "$cur" ) )
			;;
		*)
			COMPREPLY=( $( compgen -W "$subcommands" -- "$cur" ) )
			;;
	esac
}


##############################################################
## snyk iac
##############################################################
_snyk_iac()
{
	local subcommands="
		describe
        test
        update-exclude-policy
	"
	local aliases="
	"
	__snyk_subcommands "$subcommands $aliases" && return

	case "$cur" in
		-*)
			COMPREPLY=( $( compgen -W "--help" -- "$cur" ) )
			;;
		*)
			COMPREPLY=( $( compgen -W "$subcommands" -- "$cur" ) )
			;;
	esac
}

_snyk_iac_completer()
{
	local subcommands="
		--help
        "
        
	__snyk_subcommands "$subcommands" && return

	COMPREPLY=( $( compgen -W "$subcommands" -- "$cur" ) )
}
_snyk_iac_describe()
{
    _snyk_iac_completer
}

_snyk_iac_test()
{
    _snyk_iac_completer
}

_snyk_iac_update_exclude_policy()
{
    _snyk_iac_completer
}

##############################################################
## snyk ignore
##############################################################
_snyk_ignore()
{
    # This is used to get around the mac bash/nospace issue when using --flag-with-value= type params
    #
    local rvalMode=""

	local options_with_args="
        --expiry=
        --file-path-group=
        --file-path=
        --id=
        --path=
        --policy-path=
        --reason=
	"

	local all_options="$options_with_args $boolean_options"

    # On macs with old bash (like mine) the nospace option doesn't work, so have to
    # contend with the vars with args. If the current arg ends with an `=` then override
    # 
    if [[ "$cur" == *= ]]
    then
        rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev=$cur
	    cur=""
	else
	    cur=""
	fi
    elif [[ "$cur" == *=* ]]
    then
	rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev="${cur%=*}="
	    cur=${cur#*=}
	else
	    cur=""
	fi
    fi

    # if prev is an = then we are trying to find an rval. Loop back through the
    # comp words to find which one and override
    #
    if [[ "$prev" == "=" ]]
    then
	for (( word=${#COMP_WORDS[@]}-1 ; word>=0 ; word-- ))
	do
	    [[ "${COMP_WORDS[word]}" == --* ]] && prev="${COMP_WORDS[word]}"
	done
    fi

    __snyk_debug_print "prev: [$prev] cur: [$cur] reply [$COMPREPLY]"

    case "$prev" in
        --expiry=|--expiry)
            return
            ;;
        --file-path-group=|--file-path-group)
            [global|code|iac-drift]
            ;;
        --file-path=|--file-path)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;        
        --id=|--id)
            return
            ;;
            
        --path=|--path)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;        
        --policy-path=|--policy-path)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;        
        --reason=|--reason)
            return
            ;;
    esac
    
    if [[ -z $rvalMode ]]
    then        
        case "$cur" in
            -*)
                COMPREPLY=( $( compgen -W "$all_options" -- "$cur" ) )
                ;;
        esac
    fi
}

##############################################################
## snyk log4shell
##############################################################
_snyk_log4shell()
{
	local subcommands="
        -d
		--help
        "
        
	__snyk_subcommands "$subcommands" && return

	COMPREPLY=( $( compgen -W "$subcommands" -- "$cur" ) )
}

##############################################################
## snyk monitor
##############################################################
_snyk_monitor()
{
    # This could be expanded to leverage some detection mechanism for _which_
    # type of project it's in
    #
    # This is used to get around the mac bash/nospace issue when using --flag-with-value= type params
    #
    local rvalMode=""

	local options_with_args="
        --command=
        --configuration-attributes=
        --configuration-matching=
        --detection-depth=
        --exclude=
        --file=
        --init-script=
        --org=
        --package-manager=
        --policy-path=
        --project-business-criticality=
        --project-environment=
        --project-lifecycle=
        --project-name=
        --project-name-prefix=
        --project-tags=
        --reachable-timeout=
        --remote-repo-url=
        --skip-unresolved=
        --strict-out-of-sync=
        --sub-project=
        --target-reference=
	"

	local boolean_options="
        --all-projects
        --all-sub-projects
        --assets-project-name
        --dev
        --ignore-policy
        --json
        --max-depth
        --packages-folder
        --print-deps
        --prune-repeated-subdependencies, -p
        --reachable
        --scan-all-unmanaged
        --target-dir
        --trust-policies
        --unmanaged
        --yarn-workspaces
	"

	local all_options="$options_with_args $boolean_options"

    # On macs with old bash (like mine) the nospace option doesn't work, so have to
    # contend with the vars with args. If the current arg ends with an `=` then override
    # 
    if [[ "$cur" == *= ]]
    then
        rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev=$cur
	    cur=""
	else
	    cur=""
	fi
    elif [[ "$cur" == *=* ]]
    then
	rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev="${cur%=*}="
	    cur=${cur#*=}
	else
	    cur=""
	fi
    fi

    # if prev is an = then we are trying to find an rval. Loop back through the
    # comp words to find which one and override
    #
    if [[ "$prev" == "=" ]]
    then
	for (( word=${#COMP_WORDS[@]}-1 ; word>=0 ; word-- ))
	do
	    [[ "${COMP_WORDS[word]}" == --* ]] && prev="${COMP_WORDS[word]}"
	done
    fi

    __snyk_debug_print "prev: [$prev] cur: [$cur] reply [$COMPREPLY]"

    case "$prev" in
        --command=|--command)
            return
            ;;
        --configuration-attributes=|--configuration-attributes)
            return
            ;;
        --configuration-matching=|--configuration-matching)
            return
            ;;
        --detection-depth=|--detection-depth)
            return
            ;;
        --exclude=|--exclude)
            return
            ;;
        --file=|--file)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --init-script=|--init-script)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --org=|--org)
            return
            ;;
        --package-manager=|--package-manager)
            return
            ;;
        --policy-path=|--policy-path)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --project-business-criticality=|--project-business-criticality)
            __snyk_complete_severity_threshold
            return
            ;;
        --project-environment=|--project-environment)
            __snyk_complete_environment
            return
            ;;
        --project-lifecycle=|--project-lifecycle)
            __snyk_complete_lifecycle
            return
            ;;
        --project-name=|--project-name)
            return
            ;;
        --project-name-prefix=|--project-name-prefix)
            return
            ;;
        --project-tags=|--project-tags)
            return
            ;;
        --reachable-timeout=|--reachable-timeout)
            return
            ;;
        --remote-repo-url=|--remote-repo-url)
            return
            ;;
        --skip-unresolved=|--skip-unresolved)
            __snyk_complete_true_false
            return
            ;;
        --strict-out-of-sync=|--strict-out-of-sync)
            __snyk_complete_true_false
            return
            ;;
        --sub-project=|--sub-project)
            return
            ;;
        --target-reference=|--target-reference)
            return
            ;;
    esac
    
    
    if [[ -z $rvalMode ]]
    then        
        case "$cur" in
            -*)
                COMPREPLY=( $( compgen -W "$all_options" -- "$cur" ) )
                ;;
        esac
    fi
}

##############################################################
## snyk policy
##############################################################
_snyk_policy()
{
	local boolean_options="
        -d
	"

	local all_options="$boolean_options"

    __snyk_debug_print "prev: [$prev] cur: [$cur] reply [$COMPREPLY]"

    case "$cur" in
        -*)
            COMPREPLY=( $( compgen -W "$all_options" -- "$cur" ) )
            ;;
    esac
}

##############################################################
## snyk test
##############################################################
_snyk_test()
{
    # This could be expanded to leverage some detection mechanism for _which_
    # type of project it's in
    #
    # This is used to get around the mac bash/nospace issue when using --flag-with-value= type params
    #
    local rvalMode=""

	local options_with_args="
        --command=
        --configuration-attributes=
        --configuration-matching=
        --detection-depth=
        --exclude=
        --fail-on=
        --file=
        --init-script=
        --json-file-output=
        --org=
        --package-manager=
        --policy-path=
        --project-name-prefix=
        --project-name=
        --reachable-timeout=
        --remote-repo-url=
        --sarif-file-output=
        --severity-threshold=
        --show-vulnerable-paths=
        --skip-unresolved=
        --strict-out-of-sync=
        --sub-project=
        --target-reference=
	"

	local boolean_options="
        --all-projects
        --all-sub-projects
        --assets-project-name
        --dev
        --ignore-policy
        --json
        --max-depth
        --packages-folder
        --print-deps
        --prune-repeated-subdependencies, -p
        --reachable
        --sarif
        --scan-all-unmanaged
        --target-dir
        --trust-policies
        --unmanaged
        --yarn-workspaces
	"

	local all_options="$options_with_args $boolean_options"

    # On macs with old bash (like mine) the nospace option doesn't work, so have to
    # contend with the vars with args. If the current arg ends with an `=` then override
    # 
    if [[ "$cur" == *= ]]
    then
        rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev=$cur
	    cur=""
	else
	    cur=""
	fi
    elif [[ "$cur" == *=* ]]
    then
	rvalMode=true
	if ! type compopt &>/dev/null
	then
	    prev="${cur%=*}="
	    cur=${cur#*=}
	else
	    cur=""
	fi
    fi

    # if prev is an = then we are trying to find an rval. Loop back through the
    # comp words to find which one and override
    #
    if [[ "$prev" == "=" ]]
    then
	for (( word=${#COMP_WORDS[@]}-1 ; word>=0 ; word-- ))
	do
	    [[ "${COMP_WORDS[word]}" == --* ]] && prev="${COMP_WORDS[word]}"
	done
    fi
    __snyk_debug_print "prev: [$prev] cur: [$cur] reply [$COMPREPLY]"

    case "$prev" in
        --command=|--command)
            return
            ;;
        --configuration-attributes=|--configuration-attributes)
            return
            ;;
        --configuration-matching=|--configuration-matching)
            return
            ;;
        --detection-depth=|--detection-depth)
            return
            ;;
        --exclude=|--exclude)
            return
            ;;
        --fail-on=|--fail-on)
            __snyk_complete_fail_on
            return
            ;;
        --file=|--file)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --init-script=|--init-script)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --json-file-output=|--json-file-output)
            _filedir '@(json)'
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --org=|--org)
            return
            ;;
        --package-manager=|--package-manager)
            return
            ;;
        --policy-path=|--policy-path)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --project-name-prefix=|--project-name-prefix)
            return
            ;;
        --project-name=|--project-name)
            return
            ;;
        --reachable-timeout=|--reachable-timeout)
            return
            ;;
        --remote-repo-url=|--remote-repo-url)
            return
            ;;
        --sarif-file-output=|--sarif-file-output)
            _filedir
            local files=( ${COMPREPLY[@]} )
            return
            ;;
        --severity-threshold=|--severity-threshold)
            __snyk_complete_severity_threshold
            return
            ;;
        --show-vulnerable-paths=|--show-vulnerable-paths)
            __snyk_complete_vulnerable_paths
            return
            ;;
        --skip-unresolved=|--skip-unresolved)
            __snyk_complete_true_false
            return
            ;;
        --strict-out-of-sync=|--strict-out-of-sync)
            __snyk_complete_true_false
            return
            ;;
        --sub-project=|--gradle-sub-project)
            return
            ;;
        --target-reference=|--target-reference)
            return
            ;;
    esac
    
    if [[ -z $rvalMode ]]
    then        
        case "$cur" in
            -*)
                COMPREPLY=( $( compgen -W "$all_options" -- "$cur" ) )
                ;;
        esac
    fi
}

_snyk_stub() {
    # This is used to get around the mac bash/nospace issue when using --flag-with-value= type params
    #
    local rvalMode=""

	local subcommands="
		dublin
        moby
        stitch
	"
	local aliases="
		1
		2
        3
	"
	__snyk_subcommands "$subcommands $aliases" && return

	case "$cur" in
		-*)
			COMPREPLY=( $( compgen -W "--help" -- "$cur" ) )
			;;
		*)
			COMPREPLY=( $( compgen -W "$subcommands" -- "$cur" ) )
			;;
	esac
}

_snyk() {
	local previous_extglob_setting=$(shopt -p extglob)
	shopt -s extglob

	local snyk_commands=(
        auth
        code
        config
        container
        fix
        iac
        ignore
        log4shell
        monitor
        policy
        test
        sbom
        stub
	)

	local commands=(${snyk_commands[*]})

	# These options are valid as global options for all client commands
	# and valid as command options for `snyk daemon`
	local global_boolean_options="
        -d
        --help
	"
	local global_options_with_args="
		--config
	"

	# variables to cache server info, populated on demand for performance reasons
	local info_fetched server_experimental server_os
	# variables to cache client info, populated on demand for performance reasons
	local stack_orchestrator_is_kubernetes stack_orchestrator_is_swarm

	local host config context

	COMPREPLY=()
	local cur prev words cword
	_get_comp_words_by_ref -n : cur prev words cword
    
    __snyk_debug_print "prev: [$prev] cur: [$cur] reply [$COMPREPLY]"

	local command='snyk' command_pos=0 subcommand_pos
	local counter=1
	while [ "$counter" -lt "$cword" ]; do
		case "${words[$counter]}" in
			snyk)
				return 0
				;;
			# save host so that completion can use custom daemon
			--host|-H)
				(( counter++ ))
				host="${words[$counter]}"
				;;
			# save config so that completion can use custom configuration directories
			--config)
				(( counter++ ))
				config="${words[$counter]}"
				;;
			# save context so that completion can use custom daemon
			--context|-c)
				(( counter++ ))
				context="${words[$counter]}"
				;;
			$(__snyk_to_extglob "$global_options_with_args") )
				(( counter++ ))
				;;
			-*)
				;;
			=)
				(( counter++ ))
				;;
			*)
				command="${words[$counter]}"
				command_pos=$counter
				break
				;;
		esac
		(( counter++ ))
	done

	local binary="${words[0]}"
	if [[ $binary == ?(*/)snykd ]] ; then
		# for the snykd binary, we reuse completion of `snyk daemon`.
		# snykd does not have subcommands and global options.
		command=daemon
		command_pos=0
	fi
    
	local completions_func=_snyk_${command//-/_}
	declare -F $completions_func >/dev/null && $completions_func

	eval "$previous_extglob_setting"
	return 0
}

eval "$__snyk_previous_extglob_setting"
unset __snyk_previous_extglob_setting

complete -F _snyk snyk snyk-tester
# export _SNYK_COMPLETE_DEBUG=yep
