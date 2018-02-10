<?php

if ($argc < 2) {
    echo "No input\n";
    var_dump($argc);
    var_dump($argv);
    exit(1);
}

class FunctionCoverage {
    private $fxnName;
    private $coverage;
    public function __construct($fxnName, $coverage) {
        $this->fxnName = $fxnName;
        $this->coverage = $coverage;
    }
    public function getFxnName() {
        return $this->fxnName;
    }
    public function getCoverage() {
        return $this->coverage;
    }
}

class CoverageParser {
    public function parseCoverage($reportLines) {
        $getLines = false;
        $function = null;
        $coverage = [];
        foreach ($reportLines as $line) {
            if (substr($line, 0, 8) == 'Function') {
                $getLines = true;
                $function = trim(substr($line, 10, -1));
            } else if ($getLines && substr($line, 0, 5) == 'Lines') {
                $lines = explode("%", substr($line, 15))[0];
                $fxn = new FunctionCoverage($function, $lines);
                $getLines = false;
                $function = null;
                $coverage[] = $fxn;
            }
        }
        return $coverage;
    }
}

class ReportFilter {
    public function filterByFunctionPrefix(array $reports, array $filterPrefixes) {
        return array_filter($reports, function (FunctionCoverage $f) use ($filterPrefixes) {
            $l = strlen($f->getFxnName());
            foreach ($filterPrefixes as $prefix) {
                if ($l >= strlen($prefix)) {
                    if (substr($f->getFxnName(), 0, strlen($prefix)) === $prefix) {
                        return true;
                    }
                }
            }
            return false;
        });
    }
}

$coverageTarget = getenv("COVERAGE_TARGET");
if (($envFxnPrefix = getenv("COVERAGE_PREFIX_FUNCTIONS"))) {
    $filterPrefixes = explode(",", $envFxnPrefix);
} else {
    $filterPrefixes = [''];
}

$lines = explode("\n", file_get_contents($argv[1]));
$parser = new CoverageParser();
$reports = $parser->parseCoverage($lines);

$reportFilter = new ReportFilter();
$ours = $reportFilter->filterByFunctionPrefix($reports, $filterPrefixes);
echo "Function coverage analysis: \n\n";

$total = 0;
$max = 0;
foreach ($ours as $report) {
    echo " = {$report->getCoverage()}%\t{$report->getFxnName()}\n";
    $total += $report->getCoverage();
    $max += 100;
}

$percent = $total / $max * 100;

echo "\n\tCoverage was {$percent}%\n";
if ($coverageTarget && $percent < $coverageTarget) {
    echo "\tCoverage was BELOW target of {$coverageTarget}!\n\n";
    exit(1);
}

echo "\n";
