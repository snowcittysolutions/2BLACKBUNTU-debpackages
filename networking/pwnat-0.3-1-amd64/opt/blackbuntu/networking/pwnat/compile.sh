#!/usr/bin/env bash
#
# [Release]: Blackbuntu 20.04.3 LTS amd64
# [Website]: https://blackbuntu.org/p/releases/?ver=20.04.3
# [License]: http://www.gnu.org/licenses/gpl-3.0.html

## Clear screen
## ------------
function clearscreen()
{
	clear
	sleep 2s
}

## Keep alive
## ----------
function keepalive()
{
	sudo -v
	while true;
	do
		sudo -n true;
		sleep 60s;
		kill -0 "$$" || exit;
	done 2>/dev/null &
}

## Compile binary
## --------------
function compile()
{
	sudo rm -f /usr/bin/pwnat
	cd /opt/blackbuntu/networking/pwnat/
	sudo make >/dev/null 2>&1
	sudo ln -s /opt/blackbuntu/networking/pwnat/pwnat /usr/bin/pwnat
	pwnat -h
}

## Launch
## ------
function launch()
{
	clearscreen
	keepalive
	compile
}

## -------- ##
## Callback ##
## -------- ##

launch