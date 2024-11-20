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

function compile_file {
	local file="$1"
	local output_dir="$2"

	echo -e "${CYAN}Compiling:${YELLOW} $file${RESET}"

	for i in {1..3}; do
		output=$(pdflatex -shell-escape -synctex=1 -interaction=nonstopmode -file-line-error -recorder -output-directory="$output_dir" "$file" 2>&1)
		if [ $? -ne 0 ]; then
			echo -e "${RED}Error:${RESET} Compilation of $file failed on iteration $i."
			echo -e "${RED}Output:${RESET}\n$output"
			exit 1
		fi
	done
}
function build_latex {
	local file="$1"
	local output_dir="$2"

	check_file_exists "$file"

	mkdir -p "$output_dir"
	echo -e "${CYAN}Building LaTeX file: ${YELLOW}${file}${RESET}"

	# for subfile in ./pages/*.tex; do
	# 	compile_file "$subfile" "$output_dir"
	# done

	compile_file "$file" "$output_dir"

	echo -e "${GREEN}Build complete!${RESET}"
	echo -e "${CYAN}Copying generated PDF to the current directory...${RESET}"
	cp "$output_dir"/*.pdf .
	echo -e "${GREEN}PDF successfully copied.${RESET}"
}

# Main function
function main {
	local file=""
	local output_dir="$LATEX_BUILD_DIR"

	# Parse command-line arguments
	while getopts "f:o:h" opt; do
		case $opt in
		f) file="$OPTARG" ;;
		o) output_dir="$OPTARG" ;;
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

	build_latex "$file" "$output_dir"
}

main "$@"
