% SSH-AGENT-FILTER-REPLACE
% chrysn <chrysn@fsfe.org>
% 2013-10-26

# NAME

ssh-agent-filter-replace - filter all requests to the currently configured ssh-agent

# SYNOPSIS

*ssh-agent-filter-replace* arguments

# DESCRIPTION

*ssh-agent-filter-replace* is a way of invoking *ssh-agent-filter*. Instead of
offering a new `SSH_AUTH_SOCKET`, it will move the currently configured socket
to a backup location, start an *ssh-agent-filter*, and accept agent requests on
the original location.

This is particularly useful when using an agent filter instead of `ssh-add -c`;
thus, the additional information displayed by *ssh-agent-filter* can be
utilized in all confirmations.

# OPTIONS

*ssh-agent-filter-replace* passes all arguments on to *ssh-agent-filter*. See
**ssh-agent-filter**(1) for details.

# EXAMPLES

In a setup where the key with the comment `my_special_id_rsa` was previously
added with `ssh-add -c`, use this sequence to switch to *ssh-agent-filter*
based checking:

    $ ssh-add -d my_special_id_rsa
    $ ssh-add my_special_id_rsa

Now add this to your startup files:

    ssh-agent-filter-replace -C my_special_id_rsa -a

(FIXME: the `-a` option is not implemented in *ssh-agent-filter* yet, you would
have to specify all keys with `-c` explicitly until then.)

# FUTURE

It would be a reasonable extension to detect that the ssh agent is already
filtered, and on subsequent invocations replace that filter with a new one.
(Replacing it with a `-a` call would restore the original symlink, `-a` by
itself is a no-op).

The main reason for this to be a dedicated script (and to not just have an
`eval $(ssh-agent-filter ...)` in the startup files) is that it replaced
connections can be modified later, and that the filtering can be set even when
running terminals already have the `SSH_AUTH_SOCK` variable set, which can not
be changed to a global effect otherwise.

# SEE ALSO

**ssh-agent-filter**(1), **ssh-agent**(1), **ssh-add**(1)

# AUTHORS

ssh-agent-filter-replace was written by chrysn <chrysn@fsfe.org>.

Both the program and this man page are free software; you can redistribute it
and/or modify it under the terms of the GNU General Public License as published
by the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.
