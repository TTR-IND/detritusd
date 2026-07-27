# /etc/conf.d/detritus -- configuration for the detritus OpenRC service
#
# DETRITUS_NOTIFY_USER: the local username whose desktop session should
# receive freeze notifications (via notify-send) and whose processes
# detritus should restrict its victim scanning to. If left unset,
# detritus scans and can freeze processes belonging to any user on the
# system, and no desktop notification is sent when it does.
#
# This is left unset by default rather than guessed, because guessing
# wrong (e.g. picking the wrong user on a genuinely multi-user machine)
# means notifications silently go to the wrong session, or repeated
# failed `su` attempts on every freeze event -- worse than no
# notification at all. Set this explicitly for your desktop user:
#
#DETRITUS_NOTIFY_USER="yourusername"
