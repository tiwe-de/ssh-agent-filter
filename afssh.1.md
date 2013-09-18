% AFSSH(1)
% Timo Weingärtner <timo@tiwe.de>
% 2013-07-01

# NAME

afssh - wrapper around ssh-agent-filter and ssh

# SYNOPSIS

*afssh* [*ssh-agent-filter options*] -- [*ssh arguments*]

*afssh* -- [*ssh arguments*]

# DESCRIPTION

afssh (agent filtered ssh) start ssh-agent-filter(1), passing it the arguments given to afssh before the separator `--`.
If there are no arguments before `--`, whiptail(1) or dialog(1) is used to ask the user which keys to forward.

After setting up the ssh-agent-filter(1) ssh(1) is started with `-A` and the rest of the arguments (after `--`).

When ssh(1) exits, the ssh-agent-filter(1) is killed to not leave tons of them idling.

# OPTIONS

-h, \--help
:   prints a short usage description, then runs ssh-agent-filter(1) with `--help` and ssh(1) with `--help`

\--
:   mandatory separator between the options passed to ssh-agent-filter(1) and those passed to ssh(1)

# RETURN VALUES

Returns the return value of ssh(1) unless setting up the ssh-agent-filter failed, in which case the return value might be any non-zero value.

# SEE ALSO

ssh-agent-filter(1), ssh(1), ssh-agent(1), ssh-add(1), whiptail(1), dialog(1)
