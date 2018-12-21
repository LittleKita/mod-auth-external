#!/usr/bin/php
<?php
error_reporting(E_ALL);

$listen = stream_socket_server("tcp://127.0.0.1:11111");

while(true) {
   $sock = stream_socket_accept($listen, -1);
   $infos = array("CONTEXT" => "", "USER" => "", "PASS" => "");

   if(is_resource($sock)) {
      echo "Accept\r\n";
      while(!feof($sock)) {
         $line = fgets($sock, 1024*10);
         $line = str_replace("\r","",$line);
         $line = str_replace("\n","",$line);
         if(!$line) {
            break;
         }
         list($key,$val) = explode("=", $line, 2);
         $infos[$key] = $val;
      }
      if($infos["USER"] == "foo" && $infos["PASS"] == "bar") {
         fwrite($sock, "OK");
      }
      else {
         fwrite($sock, "ERR");
      }
      fclose($sock);
   }
}

?>
