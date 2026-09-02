use strict;
use warnings;
use TAP::Harness;

TAP::Harness->new({ verbosity => 1, color => 1 })->runtests('records.t');
