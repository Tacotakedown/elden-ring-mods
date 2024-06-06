
BINARIES=(
    # "adjust_fov",
    "disable_rune_loss",
    "console_logger"
    "camera_fix"
)

echo "Available binaries:"
for ((i=0; i<${#BINARIES[@]}; i++)); do
    echo "[$i] ${BINARIES[i]}"
done

read -p "Enter the indices of the binaries you want to build (comma-separated, e.g., '0,2'): " SELECTED_INDICES

IFS=',' read -ra INDICES <<< "$SELECTED_INDICES"

for index in "${INDICES[@]}"; do
    if [[ "$index" =~ ^[0-9]+$ ]] && [ "$index" -ge 0 ] && [ "$index" -lt "${#BINARIES[@]}" ]; then
        cd "${BINARIES[index]}"
        cargo build
        cd ..
    else
        echo "Invalid index: $index"
    fi
done