% SSH-ASKPASS-NOINPUT
% chrysn <chrysn@fsfe.org>
% 2013-10-26

# NAME

ssh-askpass-noinput - an `ssh-askpass` implementation for asking allow/deny questions

# SYNOPSIS

*ssh-askpass-noinput* text

# DESCRIPTION

*ssh-askpass-noinput* is an implementation of *ssh-askpass*, which does not
actually ask for a password; instead, it only asks a binary (allow/deny)
question and exits with 0 for allow and 1 for deny.

It is not intended as a general replacement for *ssh-askpass*, but for special
applications that don't care about a passphrase.

# OPTIONS

As usual with *ssh-askpass* implementations, *ssh-askpass-noinput* only takes a
single argument, which will be presented as the question.

# BACKGROUND AND APPLICATIONS

Some programs (*ssh-agent* and *ssh-agent-filter*) use *ssh-askpass* to have
users confirm actions without entering a passphrase; *ssh-agent* does this when
used via *ssh-add*'s `-c` option. They do not indicate that it is a binary
question (because in the classical *ssh-agent* invocation, there is no option to
do this), and expect the user to ignore the text input and click "OK" or
"Cancel", whereupon they read the askpass's exit status.

With programs that are known to only ask those questions, setting
`SSH_ASKPASS=ssh-askpass-noinput` in their environment will make them use this
particular implementation for their questions. It should never be installed as
`/usr/bin/ssh-askpass`.

# FUTURE

This solution is obviously a hack, which is needed until a way is established
and implemented for *ssh-askpass* to be used more flexibly.

# SEE ALSO

ssh-agent-filter(1), ssh-agent(1), ssh-askpass(1)

# AUTHORS

ssh-askpass-noinput was conceived by chrysn <chrysn@fsfe.org>.

Both the program and this man page are free software; you can redistribute it
and/or modify it under the terms of the GNU General Public License as published
by the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.
