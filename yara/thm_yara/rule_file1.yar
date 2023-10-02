rule file1_ind3x {
   meta:
      description = "file1 - file ind3x.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-09-28"
      hash1 = "5479f8cd1375364770df36e5a18262480a8f9d311e8eedb2c2390ecb233852ad"
   strings:
      $s1 = "if(buff.value == '- shell command -') buff.value = '';" fullword ascii
      $s2 = "else echo \"- shell command -\";" fullword ascii
      $s3 = "Poq99021Bibd8qdw4NBZ/7uXGFy1Pl+anH7XAc5Hn9V3mpCViltqOrEYeLOgruNToPnGfOa64UYq9SsS5xxEzXVXc1kr741dj3yso
Qsdt7zqMhrCN/Y+NSHb3DD2Hfl2" ascii
      $s4 = "elseif(isset($_REQUEST['pgsqlcon']) && ($con = pg_connect(\"host=$sqlhost user=$sqluser password=$sql
pass port=$sqlport\"))){" fullword ascii
      $s5 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
      $s6 = "setcookie(\"b374k\",$login,time() - $s_login_time);" fullword ascii
      $s7 = "http://code.google.com/p/b374k-shell" fullword ascii
      $s8 = "$rspesanb = \"Run &#39;  nc -l -v -p <i>port</i>  &#39; on your computer and press &#39;  Go !  &#39;
 button\";" fullword ascii
      $s9 = "else $s_auth = true; // $s_pass variable (password) is empty , go ahead, no login page" fullword asci
i
      $s10 = "// shell command" fullword ascii
      $s11 = "$s_pass = \"\"; // shell password, fill with password in md5 format to protect shell" fullword ascii
      $s12 = "$buff .= \"<tr><td><a href=\\\"?d=\".$parent.\"\\\">[ $folder ]</a></td><td>LINK</td><td style=\\\"t
ext-align:center;\\\">\".$ow" ascii
      $s13 = "$s_login_time = 3600 * 24 * 7;" fullword ascii
      $s14 = "setcookie(\"b374k\",md5($login),time() + $s_login_time);" fullword ascii
      $s15 = "// bind and reverse shell" fullword ascii
      $s16 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</td><td style=\\\"text
-align:center;\\\">\".$owner" ascii
      $s17 = "} // bind and reverse shell" fullword ascii
      $s18 = "elseif(isset($_REQUEST['oraclecon']) && ($con = oci_connect($sqluser,$sqlpass,$hostandport))){" full
word ascii
      $s19 = "elseif(isset($_REQUEST['mssqlcon']) && ($con = mssql_connect($hostandport,$sqluser,$sqlpass))){" ful
lword ascii
      $s20 = "if(oci_execute($st)){" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      8 of them
}
