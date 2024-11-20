#!/usr/bin/env bash

LATEX_BUILD_DIR="./latex-builds"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
RESET="\033[0m"

function usage {
	echo "Usage: $0 -f <latex-file> [-o <output-dir>] [-h]"
	echo ""
	echo "Flags:"
	echo "  -f <latex-file>  Specify the LaTeX source file to build (required)."
	echo "  -o <output-dir>  Specify the output directory (optional, defaults to './latex-builds')."
	echo "  -h               Display this help message."
}

function check_file_exists {
	local file="$1"

	if [ -z "$file" ]; then
		echo -e "${RED}Error:${RESET} LaTeX file is required. Use -f to specify the file."
		usage
		exit 1
	fi

	if [ ! -f "$file" ]; then
		echo -e "${RED}Error:${RESET} LaTeX file '$file' does not exist."
		exit 1
	fi
}

function watch {
	local file="$1"
	local output_dir="$2"
	latexmk -pvc -pdf -shell-escape -interaction=nonstopmode -outdir="$output_dir" "$file"
}

function build_latex {
	local file="$1"
	local output_dir="$2"

	check_file_exists "$file"

	mkdir -p "$output_dir"
	echo -e "${CYAN}Building LaTeX file: ${YELLOW}${file}${RESET}"

	echo -e "${CYAN}Compiling:${YELLOW} $file${RESET}"
	latexmk -pdf -shell-escape -interaction=nonstopmode -outdir="$output_dir" "$file"

	echo -e "${GREEN}Build complete!${RESET}"
}

function main {
	local file=""
	local output_dir="$LATEX_BUILD_DIR"
	local enable_watch=false

	while getopts "f:o:wh" opt; do
		case $opt in
		f) file="$OPTARG" ;;
		o) output_dir="$OPTARG" ;;
		w) enable_watch=true ;;
		h)
			usage
			exit 0
			;;
		*)
			usage
			exit 1
			;;
		esac
	done

	local base_name="${file%.tex}"
	local pdf_file="$base_name.pdf"

	if [ ! -f "$pdf_file" ]; then
		echo -e "${GREEN}Hard link created ${YELLOW}$pdf_file${RESET}"
		ln "$output_dir/$pdf_file" "$pdf_file"
	fi

	if $enable_watch; then
		watch "$file" "$output_dir"
	else
		build_latex "$file" "$output_dir"
	fi
}

main "$@"
