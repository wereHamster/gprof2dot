#!/usr/sbin/dtrace -s

#pragma D option quiet

pid$target:::entry
{
	self->caller[probefunc] = ucaller;
	self->tstamp[probefunc] = timestamp;
}

pid$target:::return
/self->tstamp[probefunc]/
{
	@calls[ufunc(self->caller[probefunc]), probemod, probefunc] = count();
	@elapsed[ufunc(self->caller[probefunc]), probemod, probefunc] = sum(timestamp - self->tstamp[probefunc]);

	self->caller[probefunc] = 0;
	self->tstamp[probefunc] = 0;
}

END
{
	printa("%A\t%s`%s\t%@d\t%@d\n", @calls, @elapsed);
}
