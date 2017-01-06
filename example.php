<?php

require __DIR__ . '/vendor/autoload.php';

use DUKPT\DerivedKey;
use DUKPT\KeySerialNumber;
use DUKPT\Utility;

// set values provided by Datecs in DOSP document
$ksn = 'FFFF987654321000000F';
$bdk = '6AC292FAA1315B4D858AB3A3D7D5933A'; // NB this is actually the IPEK - running a modified version of the library to feed in the IPEK, not BDK, for testing purposes

// example encrypted data
$encryptedHexData = 'B060EFE6117DFD6069F9C3C95442D3FAA8144417122410FA3086B43F38260FDC508887AFD299199F4DB5FBBCCA9644D42ACF3C1923C2BDAB';

$key = new KeySerialNumber($ksn);

// calculate key
$dataEncryptionRequestKey = DerivedKey::calculateDataEncryptionRequestKey($key, $bdk);

// print the keys to console
print "dataEncryptionRequestKey:" . $dataEncryptionRequestKey; // 4D3A4D2658E228A9B8DBF0B5B5BAE0DD
print "\n";

$expectedDecryptionResult = '0001005A21FC000A000102030405060708090A26AC2FB37A068AD50B158D27973931C8FB6392076124C45EDDC22495BEB0424B274E019A6B';
$decryptionResult = Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $dataEncryptionRequestKey, true)); // CBC3 mode

// print result
print "decryption result: \n" . $decryptionResult; // 0001005a21fc000a000102030405060708090a26ac2fb37a068ad50b158d27973931c8fb6392076124c45eddc22495beb0424b274e019a6b
if ($expectedDecryptionResult == $decryptionResult || strtolower($expectedDecryptionResult) == strtolower($decryptionResult)) {
  print "\ndecrypted text matches expected text! \n";
} else {
  print "decrypted text does not match expected text! Expected: \n" . $expectedDecryptionResult;
}
print "\n";

// now encrypt the data for the response
$plainHexData = '000110AF319D000505080203013E2A5CD3F080BD0EDFB1EA04A8B1A1463AC259C336726F3F99212DA1185991AFF33DE2';

// NB: the dataEncryptionRequestKey is used for both requests and responses
$expectedEncryptionResult = 'D46CA1305E749F2431FD77AF5278B32F0A182C1B5E765A75B9DFCA282C88EFF153F22A632890983AF4934E7DBD32FA6A';
$encryptionResult = Utility::removePadding(Utility::tripleDesEncrypt($plainHexData, $dataEncryptionRequestKey, true)); // CBC3 mode

// print result
print "encryption result: \n" . $encryptionResult; // d46ca1305e749f2431fd77af5278b32f0a182c1b5e765a75b9dfca282c88eff153f22a632890983af4934e7dbd32fa6a
if ($expectedEncryptionResult == $encryptionResult || strtolower($expectedEncryptionResult) == strtolower($encryptionResult)) {
  print "\nencrypted text matches expected text! \n";
} else {
  print "encrypted text does not match expected text! Expected: \n" . $expectedDecryptionResult;
}
print "\n";
