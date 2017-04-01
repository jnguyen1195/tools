<?php
// Written by Joe Nguyen ( joe_nguyen@yahoo.com )
// Description:
//   Web front page used to upload pcap file and ssh to tester to launch tcpreplay. 
//

include('/usr/share/php/Crypt/RSA.php');
include('/usr/share/php/phpseclib.autoloader.php');

function executeReplay ($TFILE,$TDIR) {
        $key = new Crypt_RSA();
         // $key->setPassword($password); // Only if your key has a passphrase
         $data = file_get_contents('/opt/utils/tester.pem');
         $key->loadKey($data);
         $ssh = new Net_SSH2('127.0.0.1', 22, 3600);

        if (!$ssh->login('tester', $key))
        {
                throw new Exception('Incorrect private key.');
        }
        $response = $ssh->exec("bash /opt/utils/REPLAY.sh -i $TFILE -l $TDIR");
        return ($response);
}
$PCAPSIZE=500000000;
$COLSIZE2=80;
$COLSIZE2=120;
$target_dir = "/opt/uploads/";
$statusScreen="How di?";
if (empty ($_FILES["fileToUpload"]["name"] )) {
      $statusScreen="Empty file";
      $target_file="NOTDEFINED";
      $imageFileType="NOTDEFINED";
} else {
      $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
      $imageFileType = pathinfo($target_file,PATHINFO_EXTENSION);	
}
$statusScreen="File uploaded=$target_file";
$uploadOk = 0;
// Check if image file is a actual image or fake image
if(isset($_POST["submit"])) {
        #$statusScreen .= "\nFile is an image ";
        $uploadOk = 1;
}
// Check if file already exists
if (file_exists($target_file)) {
   exec("rm -f $target_file",$msgarray,$result);
   $msg="";	
   for ( $j = 0 ; $j < sizeof($msgarray);$j++) {
     $msg =$msg."\n".$msgarray[$j];
   }
   $statusScreen .= "\nRemove old file $target_file."."$msg";
   #$uploadOk = 1;
} 

if ( $target_file != "NOTDEFINED" ) {
// Check file size   

   
   if ($_FILES["fileToUpload"]["size"] > $PCAPSIZE ) {
      $statusScreen .= "\nSorry, your file is too large.";
      $uploadOk = 0;
   }     
   if($imageFileType != "pcap") { 
       $statusScreen .="\nSorry, only PCAP  are allowed.";
       $uploadOk = 0;
   }
}
// Check if $uploadOk is set to 0 by an error
if ($uploadOk == 0) {
    $statusScreen .="\nSorry, your file was not uploaded.";
// Upload file
} else {
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        $statusScreen .= "\nThe file ". basename( $_FILES["fileToUpload"]["name"]). " has been uploaded."; 
  	$msg=executeReplay ($target_file, $target_dir);
  	$statusScreen .= $msg;
    } else {
        $statusScreen .= "\nSorry, there was an error uploading your file.";
    }
}
$_FILES["fileToUpload"]["name"] ="";

//
?>
<!DOCTYPE html>
<html>
<body>

<form action="pcap.php" method="post" enctype="multipart/form-data">
    
    Select PCAP file with less than <?php echo $PCAPSIZE ?> bytes to upload and replay it on the 2nd interface of this server
    Please make a note that All IPs of the current Pcap files will be substituted with the IPs with the same subnet of the 2nd interface :
    <br>
    <input type="file" name="fileToUpload" id="fileToUpload">	  
    <input type="submit" value="Upload Pcap File" name="submit">
    </br>
    <b>Log Screen</b>
    <br><textarea bgcolor="#000080"  name="statusScreen" rows="10" cols="<?php echo $COLSIZE2 ?> "readonly ><?php  echo  $statusScreen; ?> </textarea><br>


</form>

</body>
</html>