<?php
/* This script works fine with this log format:
87.223.165.221 - - [24/Jan/2019:20:32:41 +0100] "POST /page1 HTTP/2.0" 403 1388 "https://mysite.com/page1" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15"
*/

/*
 * Sorts and limits the input list (format item:count) returning a new list (format item:percentage)
 * @param array of items: files, uas, referers
 * @return array
*/
function getTop20ResultsPercents($items=array()) {
  $result = array();
  foreach($items as $k => $v) {
    $result[$k] = round((100 * $v) / array_sum($items));
  }
  arsort($result);
  return array_slice($result,0,20);
}

$filename = @$argv[1];
if(!$filename) die("Filename required\n");
$logLines = explode("\n", trim(file_get_contents($filename)));

$allowedMethods = array('HEAD', 'GET', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH');
$suspiciousResponseCodes = array(400, 401, 403, 405, 500);
$successCnt = $errorCnt = 0;
$files = $referers = $uas = $suspicious = $malicious = array();
foreach($logLines as $k => $rawLine) {
  $line = explode('"', $rawLine);
  @list($method, $file, $proto) = explode(' ',  $line[1]);
  @list($junk, $status, $duration) = explode(' ',  $line[2]);
  $referer = @$line[3];
  $ua = @$line[5];

  if($status == 200 OR $status > 300 AND $status < 310) {
    $successCnt += 1;
  } else {
    $errorCnt += 1;
  }

  @$files[$file] += 1;
  @$referers[$referer] += 1;
  @$uas[$ua] += 1;

  // BONUS: malicious ( traversal | bad method | dangerous chars)
  if(strpos('../..', $rawLine) != false OR
     !in_array($method, $allowedMethods) OR
     preg_match("/\\x[0-9A-Fa-f]/", $rawLine)) {
     $malicious[] = $rawLine;
  } elseif (in_array($status, $suspiciousResponseCodes)) {
     $suspicious[] = $rawLine;
  }
}

$results = array(
  'suspicious_requests' => $suspicious,
  'malicious_requests' => $malicious,
  'total_requests' => count($logLines),
  'success_requests' => $successCnt,
  'failed_requests' => $errorCnt,
  'top_files_percent' => getTop20ResultsPercents($files),
  'top_referers_percent' => getTop20ResultsPercents($referers),
  'top_uas_percent' => getTop20ResultsPercents($uas)
);
print_r($results);

?>
