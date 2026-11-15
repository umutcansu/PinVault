#!/usr/bin/perl
# Markdown table of a ramp: perl loadtest/table.pl RESULTS_DIR LABEL [OP]
# (reads LABEL.jsonl and LABEL-<rate>.server.csv written by ramp.sh)
use strict; use warnings; use JSON::PP;
my ($dir, $label, $opname) = @ARGV; $opname ||= 'attest';
print "| offered/s | devices | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg / max (cores) | RSS max MB | gen lag max ms | gen CPU |\n";
print "|---|---|---|---|---|---|---|---|---|---|---|\n";
open my $fh, '<', "$dir/$label.jsonl" or die $!;
while (my $line = <$fh>) {
  my $r = decode_json($line); my $op = $r->{ops}{$opname} or next;
  my $rate = $r->{offeredRate}; (my $rk = $rate) =~ s/\.0$//;
  my ($c, $n, $cmax, $m) = (0, 0, 0, 0);
  if (open my $csv, '<', "$dir/$label-$rk.server.csv") { <$csv>; while (<$csv>) { chomp; my @f = split /,/; $c += $f[1]; $n++; $cmax = $f[1] if $f[1] > $cmax; $m = $f[2] if $f[2] > $m } }
  my $total = $op->{ok} + $op->{err};
  my %e = %{$r->{errors}}; my $es = join('; ', map { my $k = $_; $k =~ s/^\S+ //; "$k $e{$_}" } sort { $e{$b} <=> $e{$a} } keys %e);
  printf "| %s | %d | %.1f | %s | %s | %s | %.2f %%%s | %.2f / %.2f | %d | %s | %.2f |\n", $rk, $r->{devices}, $op->{okPerSecond},
    $op->{p50ms} // '-', $op->{p95ms} // '-', $op->{p99ms} // '-', $total ? 100 * $op->{err} / $total : 0, $es ? " ($es)" : '',
    $n ? $c / $n / 100 : 0, $cmax / 100, $m / 1024, $r->{generatorLagMaxMs}, $r->{generatorCpuCores};
}
