#!/usr/bin/env bash
set -euo pipefail

RST=$'\e[0m'

# Foreground colors (high-contrast gradient: hot pink -> violet -> blue -> cyan)
C1=$'\e[38;2;255;80;220m'
C2=$'\e[38;2;220;90;255m'
C3=$'\e[38;2;170;110;255m'
C4=$'\e[38;2;120;140;255m'
C5=$'\e[38;2;80;190;255m'
C6=$'\e[38;2;70;235;255m'

L1="   _____                  ___ ___         "
L2="  /  _  \\   ______ ______/   |   \\  ____  "
L3=" /  /_\\  \\ /  ___//  ___/    ~    \\/  _ \\ "
L4_BASE="/    |    \\\\___ \\ \\___ \\\\    Y    "
L5="\\____|__  /____  >____  >\\___|_  / \\____/ "
L6="        \\/     \\/     \\/       \\/         "

draw() {
  local eye="$1"
  local eye_color="$2"
  local eye_pre="(  "
  local eye_post=" )"

  printf "%s%s%s\n" "$C1" "$L1" "$RST"
  printf "%s%s%s\n" "$C2" "$L2" "$RST"
  printf "%s%s%s\n" "$C3" "$L3" "$RST"
  printf "%s%s%s%s%s%s\n" "$C4" "$L4_BASE" "$eye_pre" "${eye_color}${eye}${C4}" "$eye_post" "$RST"
  printf "%s%s%s\n" "$C5" "$L5" "$RST"
  printf "%s%s%s\n" "$C6" "$L6" "$RST"
}

cleanup() {
  printf "%s" "$RST"
  tput cnorm 2>/dev/null || true
}

trap cleanup EXIT INT TERM

OPEN_EYE="<_>"
HALF_EYE="-_-"
CLOSED_EYE="---"
EYE_GLOW_A=$'\e[1;38;2;255;255;255m'
EYE_GLOW_B=$'\e[1;38;2;170;255;255m'
EYE_BLINK=$'\e[1;38;2;245;245;245m'
EYE_CHARGE_A=$'\e[1;38;2;255;255;180m'
EYE_CHARGE_B=$'\e[1;38;2;255;255;255m'
OPEN_FRAME_SLEEP=0.20
OPEN_FRAMES=15
CHARGE_FRAMES=6
CHARGE_FRAME_SLEEP=0.06

if [[ ! -t 1 ]]; then
  draw "$OPEN_EYE" "$EYE_GLOW_A"
  exit 0
fi

tput civis 2>/dev/null || true
draw "$OPEN_EYE" "$EYE_GLOW_A"
while true; do
  for ((i = 0; i < OPEN_FRAMES; i++)); do
    if (( i % 2 == 0 )); then
      eye_color="$EYE_GLOW_A"
    else
      eye_color="$EYE_GLOW_B"
    fi

    printf '\e[6A'
    draw "$OPEN_EYE" "$eye_color"
    sleep "$OPEN_FRAME_SLEEP"
  done

  for ((j = 0; j < CHARGE_FRAMES; j++)); do
    if (( j % 2 == 0 )); then
      eye_color="$EYE_CHARGE_A"
    else
      eye_color="$EYE_CHARGE_B"
    fi

    printf '\e[6A'
    draw "$OPEN_EYE" "$eye_color"
    sleep "$CHARGE_FRAME_SLEEP"
  done

  printf '\e[6A'
  draw "$HALF_EYE" "$EYE_BLINK"
  sleep 0.08

  printf '\e[6A'
  draw "$CLOSED_EYE" "$EYE_BLINK"
  sleep 0.12

  printf '\e[6A'
  draw "$HALF_EYE" "$EYE_BLINK"
  sleep 0.08
done
