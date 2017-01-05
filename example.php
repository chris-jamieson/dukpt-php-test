<?php

require __DIR__ . '/vendor/autoload.php';

use DUKPT\DerivedKey;
use DUKPT\KeySerialNumber;
use DUKPT\Utility;

// set values provided by Datecs in DOSP document
$ksn = 'FFFF987654321000000F';
$bdk = '6AC292FAA1315B4D858AB3A3D7D5933A';

// example encrypted data
$encryptedHexData = 'B060EFE6117DFD6069F9C3C95442D3FAA8144417122410FA3086B43F38260FDC508887AFD299199F4DB5FBBCCA9644D42ACF3C1923C2BDAB';

$key = new KeySerialNumber($ksn);

// calculate keys
$pinEncryptionKey = DerivedKey::calculatePinEncryptionKey($key, $bdk);
$macRequestKey = DerivedKey::calculateMacRequestKey($key, $bdk);
$macResponseKey = DerivedKey::calculateMacResponseKey($key, $bdk);
$dataEncryptionRequestKey = DerivedKey::calculateDataEncryptionRequestKey($key, $bdk);
$dataEncryptionResponseKey = DerivedKey::calculateDataEncryptionResponseKey($key, $bdk);

// print the keys to console

print "pinEncryptionKey:" . $pinEncryptionKey; // 1A322DEF09531168471566C645841CA5
print "\n";
print "macRequestKey:" . $macRequestKey; // 1A322DEF0953EE97471566C64584E35A
print "\n";
print "macResponseKey:" . $macResponseKey; // 1A322DEFF6531197471566C6BA841C5A
print "\n";
print "dataEncryptionRequestKey:" . $dataEncryptionRequestKey; // 4D3A4D2658E228A9B8DBF0B5B5BAE0DD
print "\n";
print "dataEncryptionResponseKey:" . $dataEncryptionResponseKey; // 70B372AA28A3FD7DF6CE1D8D2D6E0A78
print "\n";
print "\n";

// Note: expected decrypted output is:
// 00 01 00 5A 21 FC 00 0A 00 01 02 03 04 05 06 07 08 09 0A 26 AC 2F B3 7A 06 8A D5 0B 15 8D 27 97 39 31 C8 FB 63 92 07 61 24 C4 5E DD C2 24 95 BE B0 42 4B 27 4E 01 9A 6B

// try all key types, in ECB mode
$result1 = Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $pinEncryptionKey, false)); // ECB mode
$result2 = Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $macRequestKey, false)); // ECB mode
$result3 = Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $macResponseKey, false)); // ECB mode
$result4 = Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $dataEncryptionRequestKey, false)); // ECB mode
$result5 = Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $dataEncryptionResponseKey, false)); // ECB mode

// try all key types again, this time in CBC3 mode
$result6 = Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $pinEncryptionKey, true)); // CBC3 mode
$result7 = Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $macRequestKey, true)); // CBC3 mode
$result8 = Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $macResponseKey, true)); // CBC3 mode
$result9 = Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $dataEncryptionRequestKey, true)); // CBC3 mode
$result10 = Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $dataEncryptionResponseKey, true)); // CBC3 mode

// print results from ECB mode
print "decryption result 1: \n" . $result1; // 219cf7c878bc423477a5613ea2fba0febcc01965e28e12ef2df745fbf7b16221d230d023c04c24f6ef0bacdfdc42cd11a653ff765433fd29
print "\n";
print "decryption result 2: \n" . $result2; // 2f324f7411538d2f4c2a400f3a646c8efa72ac980d71d1064e69a19310635effafbc20315a377cca368e235ed769b89f9cca0d83b0350620
print "\n";
print "decryption result 3: \n" . $result3; // e3bce3f8071235923d118db92a41296300a05b21860c57570bf8d26ec3ab3c586947b17337828dffba65ed6521601836f96a98f6c8c57f87
print "\n";
print "decryption result 4: \n" . $result4; // b17e1d42f1d850e96c67c92b3a5839a5cf22eb83b1f28f02d5901586c776da7e91d04c5a862821e0c7d30a7b0ab2f8351abebafcbe6c3d8e
print "\n";
print "decryption result 5: \n" . $result5; // 7a0c56691bf4df3c1cbe2ace5585aec4e345a9937da35e78c3f27418bc7ca28a035efc40babf8b7b761b8c68568a4cab7885580a555f0ccd
print "\n";
print "\n";

// print results from CBC3 mode
print "decryption result 6: \n" . $result6; // 219cf7c878bc4234c7c58ed8b3865d9ed539daacb6ccc11585e301ece59572dbe2b6641cf86a2b2abf832b700edbd48eebe604ca9ea5b9fd
print "\n";
print "decryption result 7: \n" . $result7; // 2f324f7411538d2ffc4aafe92b1991ee938b6f51593302fce67de58402474e059f3a940e621173166606a4f105f0a100d17ff63f7aa342f4
print "\n";
print "decryption result 8: \n" . $result8; // e3bce3f8071235928d71625f3b3cd403695998e8d24e84ada3ec9679d18f2ca259c1054c0fa48223eaed6acaf3f901a9b4df634a02533b53
print "\n";
print "decryption result 9: \n" . $result9; // b17e1d42f1d850e9dc0726cd2b25c4c5a6db284ae5b05cf87d845191d552ca84a156f865be0e2e3c975b8dd4d82be1aa570b414074fa795a
print "\n";
print "decryption result 10: \n" . $result10; // 7a0c56691bf4df3cacdec52844f853a48abc6a5a29e18d826be6300fae58b27033d8487f829984a726930bc7841355343530a3b69fc94819
print "\n";
