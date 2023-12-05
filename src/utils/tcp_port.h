static const char *get_tcp_port(unsigned short port)
{
	switch (port) {
	case 0:
		return "Reserved";
	case 1:
		return "TCP Port Service Multiplexer";
	case 2:
		return "Management Utility";
	case 3:
		return "Compression Process";
	case 4:
		return "Unassigned";
	case 5:
		return "Remote Job Entry";
	case 6:
		return "Unassigned";
	case 7:
		return "Echo";
	case 8:
		return "Unassigned";
	case 9:
		return "Discard";
	case 10:
		return "Unassigned";
	case 11:
		return "Active Users";
	case 12:
		return "Unassigned";
	case 13:
		return "Daytime";
	case 14:
		return "Unassigned";
	case 15:
		return "Unassigned [was netstat]";
	case 16:
		return "Unassigned";
	case 17:
		return "Quote of the Day";
	case 18:
		return "Message Send Protocol (historic)";
	case 19:
		return "Character Generator";
	case 20:
		return "File Transfer [Default Data]";
	case 21:
		return "File Transfer Protocol [Control]";
	case 22:
		return "The Secure Shell (SSH) Protocol";
	case 23:
		return "Telnet";
	case 24:
		return "any private mail system";
	case 25:
		return "Simple Mail Transfer";
	case 26:
		return "Unassigned";
	case 27:
		return "NSW User System FE";
	case 28:
		return "Unassigned";
	case 29:
		return "MSG ICP";
	case 30:
		return "Unassigned";
	case 31:
		return "MSG Authentication";
	case 32:
		return "Unassigned";
	case 33:
		return "Display Support Protocol";
	case 34:
		return "Unassigned";
	case 35:
		return "any private printer server";
	case 36:
		return "Unassigned";
	case 37:
		return "Time";
	case 38:
		return "Route Access Protocol";
	case 39:
		return "Resource Location Protocol";
	case 40:
		return "Unassigned";
	case 41:
		return "Graphics";
	case 42:
		return "Host Name Server";
	case 43:
		return "Who Is";
	case 44:
		return "MPM FLAGS Protocol";
	case 45:
		return "Message Processing Module [recv]";
	case 46:
		return "MPM [default send]";
	case 47:
		return "Reserved";
	case 48:
		return "Digital Audit Daemon";
	case 49:
		return "Login Host Protocol (TACACS)";
	case 50:
		return "Remote Mail Checking Protocol";
	case 52:
		return "XNS Time Protocol";
	case 53:
		return "Domain Name Server";
	case 54:
		return "XNS Clearinghouse";
	case 55:
		return "ISI Graphics Language";
	case 56:
		return "XNS Authentication";
	case 57:
		return "any private terminal access";
	case 58:
		return "XNS Mail";
	case 59:
		return "any private file service";
	case 60:
		return "Unassigned";
	case 61:
		return "Reserved";
	case 62:
		return "ACA Services";
	case 63:
		return "whois++ IANA assigned this well-formed service name as a replacement for whois++.";
	case 64:
		return "Communications Integrator (CI)";
	case 65:
		return "TACACS-Database Service";
	case 66:
		return "Oracle SQL*NET IANA assigned this well-formed service name as a replacement for sql*net.";
	case 67:
		return "Bootstrap Protocol Server";
	case 68:
		return "Bootstrap Protocol Client";
	case 69:
		return "Trivial File Transfer";
	case 70:
		return "Gopher";
	case 71:
		return "Remote Job Service";
	case 72:
		return "Remote Job Service";
	case 73:
		return "Remote Job Service";
	case 74:
		return "Remote Job Service";
	case 75:
		return "any private dial out service";
	case 76:
		return "Distributed External Object Store";
	case 77:
		return "any private RJE service";
	case 78:
		return "vettcp";
	case 79:
		return "Finger";
	case 80:
		return "World Wide Web HTTP";
	case 82:
		return "XFER Utility";
	case 83:
		return "MIT ML Device";
	case 84:
		return "Common Trace Facility";
	case 85:
		return "MIT ML Device";
	case 86:
		return "Micro Focus Cobol";
	case 87:
		return "any private terminal link";
	case 88:
		return "Kerberos";
	case 89:
		return "SU/MIT Telnet Gateway";
	case 90:
		return "DNSIX Securit Attribute Token Map";
	case 91:
		return "MIT Dover Spooler";
	case 92:
		return "Network Printing Protocol";
	case 93:
		return "Device Control Protocol";
	case 94:
		return "Tivoli Object Dispatcher";
	case 95:
		return "SUPDUP";
	case 96:
		return "DIXIE Protocol Specification";
	case 97:
		return "Swift Remote Virtural File Protocol";
	case 98:
		return "TAC News";
	case 99:
		return "Metagram Relay";
	case 101:
		return "NIC Host Name Server";
	case 102:
		return "ISO-TSAP Class 0";
	case 103:
		return "Genesis Point-to-Point Trans Net";
	case 104:
		return "ACR-NEMA Digital Imag. & Comm. 300";
	case 105:
		return "CCSO name server protocol";
	case 106:
		return "3COM-TSMUX";
	case 107:
		return "Remote Telnet Service";
	case 108:
		return "SNA Gateway Access Server";
	case 109:
		return "Post Office Protocol - Version 2";
	case 110:
		return "Post Office Protocol - Version 3";
	case 111:
		return "SUN Remote Procedure Call";
	case 112:
		return "McIDAS Data Transmission Protocol";
	case 113:
		return "";
	case 115:
		return "Simple File Transfer Protocol";
	case 116:
		return "ANSA REX Notify";
	case 117:
		return "UUCP Path Service";
	case 118:
		return "SQL Services";
	case 119:
		return "Network News Transfer Protocol";
	case 120:
		return "CFDPTKT";
	case 121:
		return "Encore Expedited Remote Pro.Call";
	case 122:
		return "SMAKYNET";
	case 123:
		return "Network Time Protocol";
	case 124:
		return "ANSA REX Trader";
	case 125:
		return "Locus PC-Interface Net Map Ser";
	case 126:
		return "NXEdit";
	case 127:
		return "Locus PC-Interface Conn Server";
	case 128:
		return "GSS X License Verification";
	case 129:
		return "Password Generator Protocol";
	case 130:
		return "cisco FNATIVE";
	case 131:
		return "cisco TNATIVE";
	case 132:
		return "cisco SYSMAINT";
	case 133:
		return "Statistics Service";
	case 134:
		return "INGRES-NET Service";
	case 135:
		return "DCE endpoint resolution";
	case 136:
		return "PROFILE Naming System";
	case 137:
		return "NETBIOS Name Service";
	case 138:
		return "NETBIOS Datagram Service";
	case 139:
		return "NETBIOS Session Service";
	case 140:
		return "EMFIS Data Service";
	case 141:
		return "EMFIS Control Service";
	case 142:
		return "Britton-Lee IDM";
	case 143:
		return "Internet Message Access Protocol";
	case 144:
		return "Universal Management Architecture";
	case 145:
		return "UAAC Protocol";
	case 146:
		return "ISO-IP0";
	case 147:
		return "ISO-IP";
	case 148:
		return "Jargon";
	case 149:
		return "AED 512 Emulation Service";
	case 150:
		return "SQL-NET";
	case 151:
		return "HEMS";
	case 152:
		return "Background File Transfer Program";
	case 153:
		return "SGMP";
	case 154:
		return "NETSC";
	case 155:
		return "NETSC";
	case 156:
		return "SQL Service";
	case 157:
		return "KNET/VM Command/Message Protocol";
	case 158:
		return "PCMail Server";
	case 159:
		return "NSS-Routing";
	case 160:
		return "SGMP-TRAPS";
	case 161:
		return "SNMP";
	case 162:
		return "SNMPTRAP";
	case 163:
		return "CMIP/TCP Manager";
	case 164:
		return "CMIP/TCP Agent";
	case 165:
		return "Xerox";
	case 166:
		return "Sirius Systems";
	case 167:
		return "NAMP";
	case 168:
		return "RSVD";
	case 169:
		return "SEND";
	case 170:
		return "Network PostScript";
	case 171:
		return "Network Innovations Multiplex";
	case 172:
		return "Network Innovations CL/1 IANA assigned this well-formed service name as a replacement for cl/1.";
	case 173:
		return "Xyplex";
	case 174:
		return "MAILQ";
	case 175:
		return "VMNET";
	case 176:
		return "GENRAD-MUX";
	case 177:
		return "X Display Manager Control Protocol";
	case 178:
		return "NextStep Window Server";
	case 179:
		return "Border Gateway Protocol";
	case 180:
		return "Intergraph";
	case 181:
		return "Unify";
	case 182:
		return "Unisys Audit SITP";
	case 183:
		return "OCBinder";
	case 184:
		return "OCServer";
	case 185:
		return "Remote-KIS";
	case 186:
		return "KIS Protocol";
	case 187:
		return "Application Communication Interface";
	case 188:
		return "Plus Five's MUMPS";
	case 189:
		return "Queued File Transport";
	case 190:
		return "Gateway Access Control Protocol";
	case 191:
		return "Prospero Directory Service";
	case 192:
		return "OSU Network Monitoring System";
	case 193:
		return "Spider Remote Monitoring Protocol";
	case 194:
		return "Internet Relay Chat Protocol";
	case 195:
		return "DNSIX Network Level Module Audit";
	case 196:
		return "DNSIX Session Mgt Module Audit Redir";
	case 197:
		return "Directory Location Service";
	case 198:
		return "Directory Location Service Monitor";
	case 199:
		return "SMUX";
	case 200:
		return "IBM System Resource Controller";
	case 201:
		return "AppleTalk Routing Maintenance";
	case 202:
		return "AppleTalk Name Binding";
	case 203:
		return "AppleTalk Unused";
	case 204:
		return "AppleTalk Echo";
	case 205:
		return "AppleTalk Unused";
	case 206:
		return "AppleTalk Zone Information";
	case 207:
		return "AppleTalk Unused";
	case 208:
		return "AppleTalk Unused";
	case 209:
		return "The Quick Mail Transfer Protocol";
	case 210:
		return "ANSI Z39.50 IANA assigned this well-formed service name as a replacement for z39.50.";
	case 211:
		return "Texas Instruments 914C/G Terminal IANA assigned this well-formed service name as a replacement for 914c/g.";
	case 212:
		return "ATEXSSTR";
	case 213:
		return "IPX";
	case 214:
		return "VM PWSCS";
	case 215:
		return "Insignia Solutions";
	case 216:
		return "Computer Associates Int'l License Server";
	case 217:
		return "dBASE Unix";
	case 218:
		return "Netix Message Posting Protocol";
	case 219:
		return "Unisys ARPs";
	case 220:
		return "Interactive Mail Access Protocol v3";
	case 221:
		return "Berkeley rlogind with SPX auth";
	case 222:
		return "Berkeley rshd with SPX auth";
	case 223:
		return "Certificate Distribution Center";
	case 224:
		return "masqdialer";
	case 242:
		return "Direct";
	case 243:
		return "Survey Measurement";
	case 244:
		return "inbusiness";
	case 245:
		return "LINK";
	case 246:
		return "Display Systems Protocol";
	case 247:
		return "SUBNTBCST_TFTP IANA assigned this well-formed service name as a replacement for subntbcst_tftp.";
	case 248:
		return "bhfhs";
	case 256:
		return "RAP";
	case 257:
		return "Secure Electronic Transaction";
	case 259:
		return "Efficient Short Remote Operations";
	case 260:
		return "Openport";
	case 261:
		return "IIOP Name Service over TLS/SSL";
	case 262:
		return "Arcisdms";
	case 263:
		return "HDAP";
	case 264:
		return "BGMP";
	case 265:
		return "X-Bone CTL";
	case 266:
		return "SCSI on ST";
	case 267:
		return "Tobit David Service Layer";
	case 268:
		return "Tobit David Replica";
	case 269:
		return "MANET Protocols";
	case 270:
		return "Reserved";
	case 271:
		return "IETF Network Endpoint Assessment (NEA) Posture Transport Protocol over TLS (PT-TLS)";
	case 280:
		return "http-mgmt";
	case 281:
		return "Personal Link";
	case 282:
		return "Cable Port A/X";
	case 283:
		return "rescap";
	case 284:
		return "corerjd";
	case 286:
		return "FXP Communication";
	case 287:
		return "K-BLOCK";
	case 308:
		return "Novastor Backup";
	case 309:
		return "EntrustTime";
	case 310:
		return "bhmds";
	case 311:
		return "AppleShare IP WebAdmin";
	case 312:
		return "VSLMP";
	case 313:
		return "Magenta Logic";
	case 314:
		return "Opalis Robot";
	case 315:
		return "DPSI";
	case 316:
		return "decAuth";
	case 317:
		return "Zannet";
	case 318:
		return "PKIX TimeStamp";
	case 319:
		return "PTP Event";
	case 320:
		return "PTP General";
	case 321:
		return "PIP";
	case 322:
		return "RTSPS";
	case 323:
		return "Resource PKI to Router Protocol";
	case 324:
		return "Resource PKI to Router Protocol over TLS";
	case 333:
		return "Texar Security Port";
	case 344:
		return "Prospero Data Access Protocol";
	case 345:
		return "Perf Analysis Workbench";
	case 346:
		return "Zebra server";
	case 347:
		return "Fatmen Server";
	case 348:
		return "Cabletron Management Protocol";
	case 349:
		return "mftp";
	case 350:
		return "MATIP Type A";
	case 351:
		return "MATIP Type B";
	case 352:
		return "DTAG";
	case 353:
		return "NDSAUTH";
	case 354:
		return "bh611";
	case 355:
		return "DATEX-ASN";
	case 356:
		return "Cloanto Net 1";
	case 357:
		return "bhevent";
	case 358:
		return "Shrinkwrap";
	case 359:
		return "Reserved";
	case 360:
		return "scoi2odialog";
	case 361:
		return "Semantix";
	case 362:
		return "SRS Send";
	case 363:
		return "RSVP Tunnel IANA assigned this well-formed service name as a replacement for rsvp_tunnel.";
	case 364:
		return "Aurora CMGR";
	case 365:
		return "DTK";
	case 366:
		return "ODMR";
	case 367:
		return "MortgageWare";
	case 368:
		return "QbikGDP";
	case 369:
		return "rpc2portmap";
	case 370:
		return "codaauth2";
	case 371:
		return "Clearcase";
	case 372:
		return "ListProcessor";
	case 373:
		return "Legent Corporation";
	case 374:
		return "Legent Corporation";
	case 375:
		return "Hassle";
	case 376:
		return "Amiga Envoy Network Inquiry Protocol";
	case 377:
		return "NEC Corporation";
	case 378:
		return "NEC Corporation";
	case 379:
		return "TIA/EIA/IS-99 modem client";
	case 380:
		return "TIA/EIA/IS-99 modem server";
	case 381:
		return "hp performance data collector";
	case 382:
		return "hp performance data managed node";
	case 383:
		return "hp performance data alarm manager";
	case 384:
		return "A Remote Network Server System";
	case 385:
		return "IBM Application";
	case 386:
		return "ASA Message Router Object Def.";
	case 387:
		return "Appletalk Update-Based Routing Pro.";
	case 388:
		return "Unidata LDM";
	case 389:
		return "Lightweight Directory Access Protocol";
	case 390:
		return "UIS";
	case 391:
		return "SynOptics SNMP Relay Port";
	case 392:
		return "SynOptics Port Broker Port";
	case 393:
		return "Meta5";
	case 394:
		return "EMBL Nucleic Data Transfer";
	case 395:
		return "NetScout Control Protocol";
	case 396:
		return "Novell Netware over IP";
	case 397:
		return "Multi Protocol Trans. Net.";
	case 398:
		return "Kryptolan";
	case 399:
		return "ISO Transport Class 2 Non-Control over TCP";
	case 400:
		return "Oracle Secure Backup";
	case 401:
		return "Uninterruptible Power Supply";
	case 402:
		return "Genie Protocol";
	case 403:
		return "decap";
	case 404:
		return "nced";
	case 405:
		return "ncld";
	case 406:
		return "Interactive Mail Support Protocol";
	case 407:
		return "Timbuktu";
	case 408:
		return "Prospero Resource Manager Sys. Man.";
	case 409:
		return "Prospero Resource Manager Node Man.";
	case 410:
		return "DECLadebug Remote Debug Protocol";
	case 411:
		return "Remote MT Protocol";
	case 412:
		return "Trap Convention Port";
	case 413:
		return "Storage Management Services Protocol";
	case 414:
		return "InfoSeek";
	case 415:
		return "BNet";
	case 416:
		return "Silverplatter";
	case 417:
		return "Onmux";
	case 418:
		return "Hyper-G";
	case 419:
		return "Ariel 1";
	case 420:
		return "SMPTE";
	case 421:
		return "Ariel 2";
	case 422:
		return "Ariel 3";
	case 423:
		return "IBM Operations Planning and Control Start";
	case 424:
		return "IBM Operations Planning and Control Track";
	case 425:
		return "ICAD";
	case 426:
		return "smartsdp";
	case 427:
		return "Server Location";
	case 428:
		return "OCS_CMU IANA assigned this well-formed service name as a replacement for ocs_cmu.";
	case 429:
		return "OCS_AMU IANA assigned this well-formed service name as a replacement for ocs_amu.";
	case 430:
		return "UTMPSD";
	case 431:
		return "UTMPCD";
	case 432:
		return "IASD";
	case 433:
		return "NNTP for transit servers (NNSP)";
	case 434:
		return "MobileIP-Agent";
	case 435:
		return "MobilIP-MN";
	case 436:
		return "DNA-CML";
	case 437:
		return "comscm";
	case 438:
		return "dsfgw";
	case 439:
		return "dasp";
	case 440:
		return "sgcp";
	case 441:
		return "decvms-sysmgt";
	case 442:
		return "cvc_hostd IANA assigned this well-formed service name as a replacement for cvc_hostd.";
	case 443:
		return "http protocol over TLS/SSL";
	case 444:
		return "Simple Network Paging Protocol";
	case 445:
		return "Microsoft-DS";
	case 446:
		return "DDM-Remote Relational Database Access";
	case 447:
		return "DDM-Distributed File Management";
	case 448:
		return "DDM-Remote DB Access Using Secure Sockets";
	case 449:
		return "AS Server Mapper";
	case 450:
		return "Computer Supported Telecomunication Applications";
	case 451:
		return "Cray Network Semaphore server";
	case 452:
		return "Cray SFS config server";
	case 453:
		return "CreativeServer";
	case 454:
		return "ContentServer";
	case 455:
		return "CreativePartnr";
	case 456:
		return "macon-tcp";
	case 457:
		return "scohelp";
	case 458:
		return "apple quick time";
	case 459:
		return "ampr-rcmd";
	case 460:
		return "skronk";
	case 461:
		return "DataRampSrv";
	case 462:
		return "DataRampSrvSec";
	case 463:
		return "alpes";
	case 464:
		return "kpasswd";
	case 465:
		return "URL Rendezvous Directory for SSM";
	case 466:
		return "digital-vrc";
	case 467:
		return "mylex-mapd";
	case 468:
		return "proturis";
	case 469:
		return "Radio Control Protocol";
	case 470:
		return "scx-proxy";
	case 471:
		return "Mondex";
	case 472:
		return "ljk-login";
	case 473:
		return "hybrid-pop";
	case 474:
		return "tn-tl-w1";
	case 475:
		return "tcpnethaspsrv";
	case 476:
		return "tn-tl-fd1";
	case 477:
		return "ss7ns";
	case 478:
		return "spsc";
	case 479:
		return "iafserver";
	case 480:
		return "iafdbase";
	case 481:
		return "Ph service";
	case 482:
		return "bgs-nsi";
	case 483:
		return "ulpnet";
	case 484:
		return "Integra Software Management Environment";
	case 485:
		return "Air Soft Power Burst";
	case 486:
		return "avian";
	case 487:
		return "saft Simple Asynchronous File Transfer";
	case 488:
		return "gss-http";
	case 489:
		return "nest-protocol";
	case 490:
		return "micom-pfs";
	case 491:
		return "go-login";
	case 492:
		return "Transport Independent Convergence for FNA";
	case 493:
		return "Transport Independent Convergence for FNA";
	case 494:
		return "POV-Ray";
	case 495:
		return "intecourier";
	case 496:
		return "PIM-RP-DISC";
	case 497:
		return "Retrospect backup and restore service";
	case 498:
		return "siam";
	case 499:
		return "ISO ILL Protocol";
	case 500:
		return "isakmp";
	case 501:
		return "STMF";
	case 502:
		return "Modbus Application Protocol";
	case 503:
		return "Intrinsa";
	case 504:
		return "citadel";
	case 505:
		return "mailbox-lm";
	case 506:
		return "ohimsrv";
	case 507:
		return "crs";
	case 508:
		return "xvttp";
	case 509:
		return "snare";
	case 510:
		return "FirstClass Protocol";
	case 511:
		return "PassGo";
	case 512:
		return "remote process execution; authentication performed using passwords and UNIX login names";
	case 513:
		return "remote login a la telnet; automatic authentication performed based on priviledged port numbers and distributed data bases which identify authentication domains";
	case 514:
		return "cmd like exec";
	case 515:
		return "spooler";
	case 516:
		return "videotex";
	case 517:
		return "like tenex link";
	case 518:
		return "";
	case 519:
		return "unixtime";
	case 520:
		return "extended file name server";
	case 521:
		return "ripng";
	case 522:
		return "ULP";
	case 523:
		return "IBM-DB2";
	case 524:
		return "NCP";
	case 525:
		return "timeserver";
	case 526:
		return "newdate";
	case 527:
		return "Stock IXChange";
	case 528:
		return "Customer IXChange";
	case 529:
		return "IRC-SERV";
	case 530:
		return "rpc";
	case 531:
		return "chat";
	case 532:
		return "readnews";
	case 533:
		return "for emergency broadcasts";
	case 534:
		return "windream Admin";
	case 535:
		return "iiop";
	case 536:
		return "opalis-rdv";
	case 537:
		return "Networked Media Streaming Protocol";
	case 538:
		return "gdomap";
	case 539:
		return "Apertus Technologies Load Determination";
	case 540:
		return "uucpd";
	case 541:
		return "uucp-rlogin";
	case 542:
		return "commerce";
	case 543:
		return "";
	case 544:
		return "krcmd";
	case 545:
		return "appleqtcsrvr";
	case 546:
		return "DHCPv6 Client";
	case 547:
		return "DHCPv6 Server";
	case 548:
		return "AFP over TCP";
	case 549:
		return "IDFP";
	case 550:
		return "new-who";
	case 551:
		return "cybercash";
	case 552:
		return "DeviceShare";
	case 553:
		return "pirp";
	case 554:
		return "Real Time Streaming Protocol (RTSP)";
	case 555:
		return "";
	case 556:
		return "rfs server";
	case 557:
		return "openvms-sysipc";
	case 558:
		return "SDNSKMP";
	case 559:
		return "TEEDTAP";
	case 560:
		return "rmonitord";
	case 561:
		return "";
	case 562:
		return "chcmd";
	case 563:
		return "nntp protocol over TLS/SSL (was snntp)";
	case 564:
		return "plan 9 file service";
	case 565:
		return "whoami";
	case 566:
		return "streettalk";
	case 567:
		return "banyan-rpc";
	case 568:
		return "microsoft shuttle";
	case 569:
		return "microsoft rome";
	case 570:
		return "demon";
	case 571:
		return "udemon";
	case 572:
		return "sonar";
	case 573:
		return "banyan-vip";
	case 574:
		return "FTP Software Agent System";
	case 575:
		return "VEMMI";
	case 576:
		return "ipcd";
	case 577:
		return "vnas";
	case 578:
		return "ipdd";
	case 579:
		return "decbsrv";
	case 580:
		return "SNTP HEARTBEAT";
	case 581:
		return "Bundle Discovery Protocol";
	case 582:
		return "SCC Security";
	case 583:
		return "Philips Video-Conferencing";
	case 584:
		return "Key Server";
	case 586:
		return "Password Change";
	case 587:
		return "Message Submission";
	case 588:
		return "CAL";
	case 589:
		return "EyeLink";
	case 590:
		return "TNS CML";
	case 591:
		return "FileMaker";
	case 592:
		return "Eudora Set";
	case 593:
		return "HTTP RPC Ep Map";
	case 594:
		return "TPIP";
	case 595:
		return "CAB Protocol";
	case 596:
		return "SMSD";
	case 597:
		return "PTC Name Service";
	case 598:
		return "SCO Web Server Manager 3";
	case 599:
		return "Aeolon Core Protocol";
	case 600:
		return "Sun IPC server";
	case 601:
		return "Reliable Syslog Service";
	case 602:
		return "XML-RPC over BEEP";
	case 603:
		return "IDXP";
	case 604:
		return "TUNNEL";
	case 605:
		return "SOAP over BEEP";
	case 606:
		return "Cray Unified Resource Manager";
	case 607:
		return "nqs";
	case 608:
		return "Sender-Initiated/Unsolicited File Transfer";
	case 609:
		return "npmp-trap";
	case 610:
		return "npmp-local";
	case 611:
		return "npmp-gui";
	case 612:
		return "HMMP Indication";
	case 613:
		return "HMMP Operation";
	case 614:
		return "SSLshell";
	case 615:
		return "Internet Configuration Manager";
	case 616:
		return "SCO System Administration Server";
	case 617:
		return "SCO Desktop Administration Server";
	case 618:
		return "DEI-ICDA";
	case 619:
		return "Compaq EVM";
	case 620:
		return "SCO WebServer Manager";
	case 621:
		return "ESCP";
	case 622:
		return "Collaborator";
	case 623:
		return "DMTF out-of-band web services management protocol";
	case 624:
		return "Crypto Admin";
	case 625:
		return "DEC DLM IANA assigned this well-formed service name as a replacement for dec_dlm.";
	case 626:
		return "ASIA";
	case 627:
		return "PassGo Tivoli";
	case 628:
		return "QMQP";
	case 629:
		return "3Com AMP3";
	case 630:
		return "RDA";
	case 631:
		return "IPP (Internet Printing Protocol)";
	case 632:
		return "bmpp";
	case 633:
		return "Service Status update (Sterling Software)";
	case 634:
		return "ginad";
	case 635:
		return "RLZ DBase";
	case 636:
		return "ldap protocol over TLS/SSL (was sldap)";
	case 637:
		return "lanserver";
	case 638:
		return "mcns-sec";
	case 639:
		return "MSDP";
	case 640:
		return "entrust-sps";
	case 641:
		return "repcmd";
	case 642:
		return "ESRO-EMSDP V1.3";
	case 643:
		return "SANity";
	case 644:
		return "dwr";
	case 645:
		return "PSSC";
	case 646:
		return "LDP";
	case 647:
		return "DHCP Failover";
	case 648:
		return "Registry Registrar Protocol (RRP)";
	case 649:
		return "Cadview-3d - streaming 3d models over the internet";
	case 650:
		return "OBEX";
	case 651:
		return "IEEE MMS";
	case 652:
		return "HELLO_PORT";
	case 653:
		return "RepCmd";
	case 654:
		return "AODV";
	case 655:
		return "TINC";
	case 656:
		return "SPMP";
	case 657:
		return "RMC";
	case 658:
		return "TenFold";
	case 660:
		return "MacOS Server Admin";
	case 661:
		return "HAP";
	case 662:
		return "PFTP";
	case 663:
		return "PureNoise";
	case 664:
		return "DMTF out-of-band secure web services management protocol";
	case 665:
		return "Sun DR";
	case 666:
		return "";
	case 667:
		return "campaign contribution disclosures - SDR Technologies";
	case 668:
		return "MeComm";
	case 669:
		return "MeRegister";
	case 670:
		return "VACDSM-SWS";
	case 671:
		return "VACDSM-APP";
	case 672:
		return "VPPS-QUA";
	case 673:
		return "CIMPLEX";
	case 674:
		return "ACAP";
	case 675:
		return "DCTP";
	case 676:
		return "VPPS Via";
	case 677:
		return "Virtual Presence Protocol";
	case 678:
		return "GNU Generation Foundation NCP";
	case 679:
		return "MRM";
	case 680:
		return "entrust-aaas";
	case 681:
		return "entrust-aams";
	case 682:
		return "XFR";
	case 683:
		return "CORBA IIOP";
	case 684:
		return "CORBA IIOP SSL";
	case 685:
		return "MDC Port Mapper";
	case 686:
		return "Hardware Control Protocol Wismar";
	case 687:
		return "asipregistry";
	case 688:
		return "ApplianceWare managment protocol";
	case 689:
		return "NMAP";
	case 690:
		return "Velneo Application Transfer Protocol";
	case 691:
		return "MS Exchange Routing";
	case 692:
		return "Hyperwave-ISP";
	case 693:
		return "almanid Connection Endpoint";
	case 694:
		return "ha-cluster";
	case 695:
		return "IEEE-MMS-SSL";
	case 696:
		return "RUSHD";
	case 697:
		return "UUIDGEN";
	case 698:
		return "OLSR";
	case 699:
		return "Access Network";
	case 700:
		return "Extensible Provisioning Protocol";
	case 701:
		return "Link Management Protocol (LMP)";
	case 702:
		return "IRIS over BEEP";
	case 704:
		return "errlog copy/server daemon";
	case 705:
		return "AgentX";
	case 706:
		return "SILC";
	case 707:
		return "Borland DSJ";
	case 709:
		return "Entrust Key Management Service Handler";
	case 710:
		return "Entrust Administration Service Handler";
	case 711:
		return "Cisco TDP";
	case 712:
		return "TBRPF";
	case 713:
		return "IRIS over XPC";
	case 714:
		return "IRIS over XPCS";
	case 715:
		return "IRIS-LWZ";
	case 729:
		return "IBM NetView DM/6000 Server/Client";
	case 730:
		return "IBM NetView DM/6000 send/tcp";
	case 731:
		return "IBM NetView DM/6000 receive/tcp";
	case 741:
		return "netGW";
	case 742:
		return "Network based Rev. Cont. Sys.";
	case 744:
		return "Flexible License Manager";
	case 747:
		return "Fujitsu Device Control";
	case 748:
		return "Russell Info Sci Calendar Manager";
	case 749:
		return "kerberos administration";
	case 750:
		return "";
	case 751:
		return "";
	case 752:
		return "";
	case 753:
		return "";
	case 754:
		return "send";
	case 758:
		return "";
	case 759:
		return "";
	case 760:
		return "";
	case 761:
		return "";
	case 762:
		return "";
	case 763:
		return "";
	case 764:
		return "";
	case 765:
		return "";
	case 767:
		return "phone";
	case 769:
		return "";
	case 770:
		return "";
	case 771:
		return "";
	case 772:
		return "";
	case 773:
		return "";
	case 774:
		return "";
	case 775:
		return "";
	case 776:
		return "";
	case 777:
		return "Multiling HTTP";
	case 780:
		return "";
	case 800:
		return "IANA assigned this well-formed service name as a replacement for mdbs_daemon.";
	case 801:
		return "";
	case 802:
		return "Modbus Application Protocol Secure";
	case 810:
		return "FCP";
	case 828:
		return "itm-mcell-s";
	case 829:
		return "PKIX-3 CA/RA";
	case 830:
		return "NETCONF over SSH";
	case 831:
		return "NETCONF over BEEP";
	case 832:
		return "NETCONF for SOAP over HTTPS";
	case 833:
		return "NETCONF for SOAP over BEEP";
	case 847:
		return "dhcp-failover 2";
	case 848:
		return "GDOI";
	case 853:
		return "DNS query-response protocol run over TLS";
	case 854:
		return "Dynamic Link Exchange Protocol (DLEP)";
	case 860:
		return "iSCSI";
	case 861:
		return "OWAMP-Control";
	case 862:
		return "TWAMP-Control";
	case 873:
		return "rsync";
	case 886:
		return "ICL coNETion locate server";
	case 887:
		return "ICL coNETion server info IANA assigned this well-formed service name as a replacement for iclcnet_svinfo.";
	case 888:
		return "AccessBuilder";
	case 900:
		return "OMG Initial Refs";
	case 901:
		return "SMPNAMERES";
	case 902:
		return "self documenting Telnet Door";
	case 903:
		return "self documenting Telnet Panic Door";
	case 910:
		return "Kerberized Internet Negotiation of Keys (KINK)";
	case 911:
		return "xact-backup";
	case 912:
		return "APEX relay-relay service";
	case 913:
		return "APEX endpoint-relay service";
	case 914:
		return "Reserved";
	case 915:
		return "Reserved";
	case 953:
		return "BIND9 remote name daemon controller";
	case 989:
		return "ftp protocol";
	case 990:
		return "ftp protocol";
	case 991:
		return "Netnews Administration System";
	case 992:
		return "telnet protocol over TLS/SSL";
	case 993:
		return "IMAP over TLS protocol";
	case 994:
		return "Reserved";
	case 995:
		return "POP3 over TLS protocol";
	case 996:
		return "vsinet";
	case 997:
		return "";
	case 998:
		return "";
	case 999:
		return "";
	case 1000:
		return "";
	case 1001:
		return "HTTP Web Push";
	case 1010:
		return "surf";
	case 1021:
		return "RFC3692-style Experiment 1";
	case 1022:
		return "RFC3692-style Experiment 2";
	case 1023:
		return "Reserved";
	case 1024:
		return "Reserved";
	case 1025:
		return "network blackjack";
	case 1026:
		return "Calendar Access Protocol";
	case 1027:
		return "Reserved";
	case 1029:
		return "Solid Mux Server";
	case 1033:
		return "local netinfo port";
	case 1034:
		return "ActiveSync Notifications";
	case 1035:
		return "MX-XR RPC";
	case 1036:
		return "Nebula Secure Segment Transfer Protocol";
	case 1037:
		return "AMS";
	case 1038:
		return "Message Tracking Query Protocol";
	case 1039:
		return "Streamlined Blackhole";
	case 1040:
		return "Netarx Netcare";
	case 1041:
		return "AK2 Product";
	case 1042:
		return "Subnet Roaming";
	case 1043:
		return "BOINC Client Control";
	case 1044:
		return "Dev Consortium Utility";
	case 1045:
		return "Fingerprint Image Transfer Protocol";
	case 1046:
		return "WebFilter Remote Monitor";
	case 1047:
		return "Sun's NEO Object Request Broker";
	case 1048:
		return "Sun's NEO Object Request Broker";
	case 1049:
		return "Tobit David Postman VPMN";
	case 1050:
		return "CORBA Management Agent";
	case 1051:
		return "Optima VNET";
	case 1052:
		return "Dynamic DNS Tools";
	case 1053:
		return "Remote Assistant (RA)";
	case 1054:
		return "BRVREAD";
	case 1055:
		return "ANSYS - License Manager";
	case 1056:
		return "VFO";
	case 1057:
		return "STARTRON";
	case 1058:
		return "nim";
	case 1059:
		return "nimreg";
	case 1060:
		return "POLESTAR";
	case 1061:
		return "KIOSK";
	case 1062:
		return "Veracity";
	case 1063:
		return "KyoceraNetDev";
	case 1064:
		return "JSTEL";
	case 1065:
		return "SYSCOMLAN";
	case 1066:
		return "FPO-FNS";
	case 1067:
		return "Installation Bootstrap Proto. Serv. IANA assigned this well-formed service name as a replacement for instl_boots.";
	case 1068:
		return "Installation Bootstrap Proto. Cli. IANA assigned this well-formed service name as a replacement for instl_bootc.";
	case 1069:
		return "COGNEX-INSIGHT";
	case 1070:
		return "GMRUpdateSERV";
	case 1071:
		return "BSQUARE-VOIP";
	case 1072:
		return "CARDAX";
	case 1073:
		return "Bridge Control";
	case 1074:
		return "Warmspot Management Protocol";
	case 1075:
		return "RDRMSHC";
	case 1076:
		return "DAB STI-C";
	case 1077:
		return "IMGames";
	case 1078:
		return "Avocent Proxy Protocol";
	case 1079:
		return "ASPROVATalk";
	case 1080:
		return "Socks";
	case 1081:
		return "PVUNIWIEN";
	case 1082:
		return "AMT-ESD-PROT";
	case 1083:
		return "Anasoft License Manager";
	case 1084:
		return "Anasoft License Manager";
	case 1085:
		return "Web Objects";
	case 1086:
		return "CPL Scrambler Logging";
	case 1087:
		return "CPL Scrambler Internal";
	case 1088:
		return "CPL Scrambler Alarm Log";
	case 1089:
		return "FF Annunciation";
	case 1090:
		return "FF Fieldbus Message Specification";
	case 1091:
		return "FF System Management";
	case 1092:
		return "Open Business Reporting Protocol";
	case 1093:
		return "PROOFD";
	case 1094:
		return "ROOTD";
	case 1095:
		return "NICELink";
	case 1096:
		return "Common Name Resolution Protocol";
	case 1097:
		return "Sun Cluster Manager";
	case 1098:
		return "RMI Activation";
	case 1099:
		return "RMI Registry";
	case 1100:
		return "MCTP";
	case 1101:
		return "PT2-DISCOVER";
	case 1102:
		return "ADOBE SERVER 1";
	case 1103:
		return "ADOBE SERVER 2";
	case 1104:
		return "XRL";
	case 1105:
		return "FTRANHC";
	case 1106:
		return "ISOIPSIGPORT-1";
	case 1107:
		return "ISOIPSIGPORT-2";
	case 1108:
		return "ratio-adp";
	case 1110:
		return "Start web admin server";
	case 1111:
		return "LM Social Server";
	case 1112:
		return "Intelligent Communication Protocol";
	case 1113:
		return "Licklider Transmission Protocol";
	case 1114:
		return "Mini SQL";
	case 1115:
		return "ARDUS Transfer";
	case 1116:
		return "ARDUS Control";
	case 1117:
		return "ARDUS Multicast Transfer";
	case 1118:
		return "SACRED";
	case 1119:
		return "Battle.net Chat/Game Protocol";
	case 1120:
		return "Battle.net File Transfer Protocol";
	case 1121:
		return "Datalode RMPP";
	case 1122:
		return "availant-mgr";
	case 1123:
		return "Murray";
	case 1124:
		return "HP VMM Control";
	case 1125:
		return "HP VMM Agent";
	case 1126:
		return "HP VMM Agent";
	case 1127:
		return "KWDB Remote Communication";
	case 1128:
		return "SAPHostControl over SOAP/HTTP";
	case 1129:
		return "SAPHostControl over SOAP/HTTPS";
	case 1130:
		return "CAC App Service Protocol";
	case 1131:
		return "CAC App Service Protocol Encripted";
	case 1132:
		return "KVM-via-IP Management Service";
	case 1133:
		return "Data Flow Network";
	case 1134:
		return "MicroAPL APLX";
	case 1135:
		return "OmniVision Communication Service";
	case 1136:
		return "HHB Gateway Control";
	case 1137:
		return "TRIM Workgroup Service";
	case 1138:
		return "encrypted admin requests IANA assigned this well-formed service name as a replacement for encrypted_admin.";
	case 1139:
		return "Enterprise Virtual Manager";
	case 1140:
		return "AutoNOC Network Operations Protocol";
	case 1141:
		return "User Message Service";
	case 1142:
		return "User Discovery Service";
	case 1143:
		return "Infomatryx Exchange";
	case 1144:
		return "Fusion Script";
	case 1145:
		return "X9 iCue Show Control";
	case 1146:
		return "audit transfer";
	case 1147:
		return "CAPIoverLAN";
	case 1148:
		return "Elfiq Replication Service";
	case 1149:
		return "BlueView Sonar Service";
	case 1150:
		return "Blaze File Server";
	case 1151:
		return "Unizensus Login Server";
	case 1152:
		return "Winpopup LAN Messenger";
	case 1153:
		return "ANSI C12.22 Port";
	case 1154:
		return "Community Service";
	case 1155:
		return "Network File Access";
	case 1156:
		return "iasControl OMS";
	case 1157:
		return "Oracle iASControl";
	case 1158:
		return "dbControl OMS";
	case 1159:
		return "Oracle OMS";
	case 1160:
		return "DB Lite Mult-User Server";
	case 1161:
		return "Health Polling";
	case 1162:
		return "Health Trap";
	case 1163:
		return "SmartDialer Data Protocol";
	case 1164:
		return "QSM Proxy Service";
	case 1165:
		return "QSM GUI Service";
	case 1166:
		return "QSM RemoteExec";
	case 1167:
		return "Cisco IP SLAs Control Protocol";
	case 1168:
		return "VChat Conference Service";
	case 1169:
		return "TRIPWIRE";
	case 1170:
		return "AT+C License Manager";
	case 1171:
		return "AT+C FmiApplicationServer";
	case 1172:
		return "DNA Protocol";
	case 1173:
		return "D-Cinema Request-Response";
	case 1174:
		return "FlashNet Remote Admin";
	case 1175:
		return "Dossier Server";
	case 1176:
		return "Indigo Home Server";
	case 1177:
		return "DKMessenger Protocol";
	case 1178:
		return "SGI Storage Manager";
	case 1179:
		return "Backup To Neighbor";
	case 1180:
		return "Millicent Client Proxy";
	case 1181:
		return "3Com Net Management";
	case 1182:
		return "AcceleNet Control";
	case 1183:
		return "LL Surfup HTTP";
	case 1184:
		return "LL Surfup HTTPS";
	case 1185:
		return "Catchpole port";
	case 1186:
		return "MySQL Cluster Manager";
	case 1187:
		return "Alias Service";
	case 1188:
		return "HP Web Admin";
	case 1189:
		return "Unet Connection";
	case 1190:
		return "CommLinx GPS / AVL System";
	case 1191:
		return "General Parallel File System";
	case 1192:
		return "caids sensors channel";
	case 1193:
		return "Five Across Server";
	case 1194:
		return "OpenVPN";
	case 1195:
		return "RSF-1 clustering";
	case 1196:
		return "Network Magic";
	case 1197:
		return "Carrius Remote Access";
	case 1198:
		return "cajo reference discovery";
	case 1199:
		return "DMIDI";
	case 1200:
		return "SCOL";
	case 1201:
		return "Nucleus Sand Database Server";
	case 1202:
		return "caiccipc";
	case 1203:
		return "License Validation";
	case 1204:
		return "Log Request Listener";
	case 1205:
		return "Accord-MGC";
	case 1206:
		return "Anthony Data";
	case 1207:
		return "MetaSage";
	case 1208:
		return "SEAGULL AIS";
	case 1209:
		return "IPCD3";
	case 1210:
		return "EOSS";
	case 1211:
		return "Groove DPP";
	case 1212:
		return "lupa";
	case 1213:
		return "Medtronic/Physio-Control LIFENET";
	case 1214:
		return "KAZAA";
	case 1215:
		return "scanSTAT 1.0";
	case 1216:
		return "ETEBAC 5";
	case 1217:
		return "HPSS NonDCE Gateway";
	case 1218:
		return "AeroFlight-ADs";
	case 1219:
		return "AeroFlight-Ret";
	case 1220:
		return "QT SERVER ADMIN";
	case 1221:
		return "SweetWARE Apps";
	case 1222:
		return "SNI R&D network";
	case 1223:
		return "TrulyGlobal Protocol";
	case 1224:
		return "VPNz";
	case 1225:
		return "SLINKYSEARCH";
	case 1226:
		return "STGXFWS";
	case 1227:
		return "DNS2Go";
	case 1228:
		return "FLORENCE";
	case 1229:
		return "ZENworks Tiered Electronic Distribution";
	case 1230:
		return "Periscope";
	case 1231:
		return "menandmice-lpm";
	case 1232:
		return "Remote systems monitoring";
	case 1233:
		return "Universal App Server";
	case 1234:
		return "Infoseek Search Agent";
	case 1235:
		return "mosaicsyssvc1";
	case 1236:
		return "bvcontrol";
	case 1237:
		return "tsdos390";
	case 1238:
		return "hacl-qs";
	case 1239:
		return "NMSD";
	case 1240:
		return "Instantia";
	case 1241:
		return "nessus";
	case 1242:
		return "NMAS over IP";
	case 1243:
		return "SerialGateway";
	case 1244:
		return "isbconference1";
	case 1245:
		return "isbconference2";
	case 1246:
		return "payrouter";
	case 1247:
		return "VisionPyramid";
	case 1248:
		return "hermes";
	case 1249:
		return "Mesa Vista Co";
	case 1250:
		return "swldy-sias";
	case 1251:
		return "servergraph";
	case 1252:
		return "bspne-pcc";
	case 1253:
		return "q55-pcc";
	case 1254:
		return "de-noc";
	case 1255:
		return "de-cache-query";
	case 1256:
		return "de-server";
	case 1257:
		return "Shockwave 2";
	case 1258:
		return "Open Network Library";
	case 1259:
		return "Open Network Library Voice";
	case 1260:
		return "ibm-ssd";
	case 1261:
		return "mpshrsv";
	case 1262:
		return "QNTS-ORB";
	case 1263:
		return "dka";
	case 1264:
		return "PRAT";
	case 1265:
		return "DSSIAPI";
	case 1266:
		return "DELLPWRAPPKS";
	case 1267:
		return "eTrust Policy Compliance";
	case 1268:
		return "PROPEL-MSGSYS";
	case 1269:
		return "WATiLaPP";
	case 1270:
		return "Microsoft Operations Manager";
	case 1271:
		return "eXcW";
	case 1272:
		return "CSPMLockMgr";
	case 1273:
		return "EMC-Gateway";
	case 1274:
		return "t1distproc";
	case 1275:
		return "ivcollector";
	case 1276:
		return "Reserved";
	case 1277:
		return "mqs";
	case 1278:
		return "Dell Web Admin 1";
	case 1279:
		return "Dell Web Admin 2";
	case 1280:
		return "Pictrography";
	case 1281:
		return "healthd";
	case 1282:
		return "Emperion";
	case 1283:
		return "Product Information";
	case 1284:
		return "IEE-QFX";
	case 1285:
		return "neoiface";
	case 1286:
		return "netuitive";
	case 1287:
		return "RouteMatch Com";
	case 1288:
		return "NavBuddy";
	case 1289:
		return "JWalkServer";
	case 1290:
		return "WinJaServer";
	case 1291:
		return "SEAGULLLMS";
	case 1292:
		return "dsdn";
	case 1293:
		return "PKT-KRB-IPSec";
	case 1294:
		return "CMMdriver";
	case 1295:
		return "End-by-Hop Transmission Protocol";
	case 1296:
		return "dproxy";
	case 1297:
		return "sdproxy";
	case 1298:
		return "lpcp";
	case 1299:
		return "hp-sci";
	case 1300:
		return "H.323 Secure Call Control Signalling";
	case 1301:
		return "Reserved";
	case 1302:
		return "Reserved";
	case 1303:
		return "sftsrv";
	case 1304:
		return "Boomerang";
	case 1305:
		return "pe-mike";
	case 1306:
		return "RE-Conn-Proto";
	case 1307:
		return "Pacmand";
	case 1308:
		return "Optical Domain Service Interconnect (ODSI)";
	case 1309:
		return "JTAG server";
	case 1310:
		return "Husky";
	case 1311:
		return "RxMon";
	case 1312:
		return "STI Envision";
	case 1313:
		return "BMC_PATROLDB IANA assigned this well-formed service name as a replacement for bmc_patroldb.";
	case 1314:
		return "Photoscript Distributed Printing System";
	case 1315:
		return "E.L.S.";
	case 1316:
		return "Exbit-ESCP";
	case 1317:
		return "vrts-ipcserver";
	case 1318:
		return "krb5gatekeeper";
	case 1319:
		return "AMX-ICSP";
	case 1320:
		return "AMX-AXBNET";
	case 1321:
		return "PIP";
	case 1322:
		return "Novation";
	case 1323:
		return "brcd";
	case 1324:
		return "delta-mcp";
	case 1325:
		return "DX-Instrument";
	case 1326:
		return "WIMSIC";
	case 1327:
		return "Ultrex";
	case 1328:
		return "EWALL";
	case 1329:
		return "netdb-export";
	case 1330:
		return "StreetPerfect";
	case 1331:
		return "intersan";
	case 1332:
		return "PCIA RXP-B";
	case 1333:
		return "Password Policy";
	case 1334:
		return "writesrv";
	case 1335:
		return "Digital Notary Protocol";
	case 1336:
		return "Instant Service Chat";
	case 1337:
		return "menandmice DNS";
	case 1338:
		return "WMC-log-svr";
	case 1339:
		return "kjtsiteserver";
	case 1340:
		return "NAAP";
	case 1341:
		return "QuBES";
	case 1342:
		return "ESBroker";
	case 1343:
		return "re101";
	case 1344:
		return "ICAP";
	case 1345:
		return "VPJP";
	case 1346:
		return "Alta Analytics License Manager";
	case 1347:
		return "multi media conferencing";
	case 1348:
		return "multi media conferencing";
	case 1349:
		return "Registration Network Protocol";
	case 1350:
		return "Registration Network Protocol";
	case 1351:
		return "Digital Tool Works (MIT)";
	case 1352:
		return "Lotus Note";
	case 1353:
		return "Relief Consulting";
	case 1354:
		return "Five Across XSIP Network";
	case 1355:
		return "Intuitive Edge";
	case 1356:
		return "CuillaMartin Company";
	case 1357:
		return "Electronic PegBoard";
	case 1358:
		return "CONNLCLI";
	case 1359:
		return "FTSRV";
	case 1360:
		return "MIMER";
	case 1361:
		return "LinX";
	case 1362:
		return "TimeFlies";
	case 1363:
		return "Network DataMover Requester";
	case 1364:
		return "Network DataMover Server";
	case 1365:
		return "Network Software Associates";
	case 1366:
		return "Novell NetWare Comm Service Platform";
	case 1367:
		return "DCS";
	case 1368:
		return "ScreenCast";
	case 1369:
		return "GlobalView to Unix Shell";
	case 1370:
		return "Unix Shell to GlobalView";
	case 1371:
		return "Fujitsu Config Protocol";
	case 1372:
		return "Fujitsu Config Protocol";
	case 1373:
		return "Chromagrafx";
	case 1374:
		return "EPI Software Systems";
	case 1375:
		return "Bytex";
	case 1376:
		return "IBM Person to Person Software";
	case 1377:
		return "Cichlid License Manager";
	case 1378:
		return "Elan License Manager";
	case 1379:
		return "Integrity Solutions";
	case 1380:
		return "Telesis Network License Manager";
	case 1381:
		return "Apple Network License Manager";
	case 1382:
		return "udt_os IANA assigned this well-formed service name as a replacement for udt_os.";
	case 1383:
		return "GW Hannaway Network License Manager";
	case 1384:
		return "Objective Solutions License Manager";
	case 1385:
		return "Atex Publishing License Manager IANA assigned this well-formed service name as a replacement for atex_elmd.";
	case 1386:
		return "CheckSum License Manager";
	case 1387:
		return "Computer Aided Design Software Inc LM";
	case 1388:
		return "Objective Solutions DataBase Cache";
	case 1389:
		return "Document Manager";
	case 1390:
		return "Storage Controller";
	case 1391:
		return "Storage Access Server";
	case 1392:
		return "Print Manager";
	case 1393:
		return "Network Log Server";
	case 1394:
		return "Network Log Client";
	case 1395:
		return "PC Workstation Manager software";
	case 1396:
		return "DVL Active Mail";
	case 1397:
		return "Audio Active Mail";
	case 1398:
		return "Video Active Mail";
	case 1399:
		return "Cadkey License Manager";
	case 1400:
		return "Cadkey Tablet Daemon";
	case 1401:
		return "Goldleaf License Manager";
	case 1402:
		return "Prospero Resource Manager";
	case 1403:
		return "Prospero Resource Manager";
	case 1404:
		return "Infinite Graphics License Manager";
	case 1405:
		return "IBM Remote Execution Starter";
	case 1406:
		return "NetLabs License Manager";
	case 1407:
		return "TIBET Data Server";
	case 1408:
		return "Sophia License Manager";
	case 1409:
		return "Here License Manager";
	case 1410:
		return "HiQ License Manager";
	case 1411:
		return "AudioFile";
	case 1412:
		return "InnoSys";
	case 1413:
		return "Innosys-ACL";
	case 1414:
		return "IBM MQSeries";
	case 1415:
		return "DBStar";
	case 1416:
		return "Novell LU6.2 IANA assigned this well-formed service name as a replacement for novell-lu6.2.";
	case 1417:
		return "Timbuktu Service 1 Port";
	case 1418:
		return "Timbuktu Service 2 Port";
	case 1419:
		return "Timbuktu Service 3 Port";
	case 1420:
		return "Timbuktu Service 4 Port";
	case 1421:
		return "Gandalf License Manager";
	case 1422:
		return "Autodesk License Manager";
	case 1423:
		return "Essbase Arbor Software";
	case 1424:
		return "Hybrid Encryption Protocol";
	case 1425:
		return "Zion Software License Manager";
	case 1426:
		return "Satellite-data Acquisition System 1";
	case 1427:
		return "mloadd monitoring tool";
	case 1428:
		return "Informatik License Manager";
	case 1429:
		return "Hypercom NMS";
	case 1430:
		return "Hypercom TPDU";
	case 1431:
		return "Reverse Gossip Transport";
	case 1432:
		return "Blueberry Software License Manager";
	case 1433:
		return "Microsoft-SQL-Server";
	case 1434:
		return "Microsoft-SQL-Monitor";
	case 1435:
		return "IBM CICS";
	case 1436:
		return "Satellite-data Acquisition System 2";
	case 1437:
		return "Tabula";
	case 1438:
		return "Eicon Security Agent/Server";
	case 1439:
		return "Eicon X25/SNA Gateway";
	case 1440:
		return "Eicon Service Location Protocol";
	case 1441:
		return "Cadis License Management";
	case 1442:
		return "Cadis License Management";
	case 1443:
		return "Integrated Engineering Software";
	case 1444:
		return "Marcam  License Management";
	case 1445:
		return "Proxima License Manager";
	case 1446:
		return "Optical Research Associates License Manager";
	case 1447:
		return "Applied Parallel Research LM";
	case 1448:
		return "OpenConnect License Manager";
	case 1449:
		return "PEport";
	case 1450:
		return "Tandem Distributed Workbench Facility";
	case 1451:
		return "IBM Information Management";
	case 1452:
		return "GTE Government Systems License Man";
	case 1453:
		return "Genie License Manager";
	case 1454:
		return "interHDL License Manager IANA assigned this well-formed service name as a replacement for interhdl_elmd.";
	case 1455:
		return "ESL License Manager";
	case 1456:
		return "DCA";
	case 1457:
		return "Valisys License Manager";
	case 1458:
		return "Nichols Research Corp.";
	case 1459:
		return "Proshare Notebook Application";
	case 1460:
		return "Proshare Notebook Application";
	case 1461:
		return "IBM Wireless LAN IANA assigned this well-formed service name as a replacement for ibm_wrless_lan.";
	case 1462:
		return "World License Manager";
	case 1463:
		return "Nucleus";
	case 1464:
		return "MSL License Manager IANA assigned this well-formed service name as a replacement for msl_lmd.";
	case 1465:
		return "Pipes Platform";
	case 1466:
		return "Ocean Software License Manager";
	case 1467:
		return "CSDMBASE";
	case 1468:
		return "CSDM";
	case 1469:
		return "Active Analysis Limited License Manager";
	case 1470:
		return "Universal Analytics";
	case 1471:
		return "csdmbase";
	case 1472:
		return "csdm";
	case 1473:
		return "OpenMath";
	case 1474:
		return "Telefinder";
	case 1475:
		return "Taligent License Manager";
	case 1476:
		return "clvm-cfg";
	case 1477:
		return "ms-sna-server";
	case 1478:
		return "ms-sna-base";
	case 1479:
		return "dberegister";
	case 1480:
		return "PacerForum";
	case 1481:
		return "AIRS";
	case 1482:
		return "Miteksys License Manager";
	case 1483:
		return "AFS License Manager";
	case 1484:
		return "Confluent License Manager";
	case 1485:
		return "LANSource";
	case 1486:
		return "nms_topo_serv IANA assigned this well-formed service name as a replacement for nms_topo_serv.";
	case 1487:
		return "LocalInfoSrvr";
	case 1488:
		return "DocStor";
	case 1489:
		return "dmdocbroker";
	case 1490:
		return "insitu-conf";
	case 1492:
		return "stone-design-1";
	case 1493:
		return "netmap_lm IANA assigned this well-formed service name as a replacement for netmap_lm.";
	case 1494:
		return "ica";
	case 1495:
		return "cvc";
	case 1496:
		return "liberty-lm";
	case 1497:
		return "rfx-lm";
	case 1498:
		return "Sybase SQL Any";
	case 1499:
		return "Federico Heinz Consultora";
	case 1500:
		return "VLSI License Manager";
	case 1501:
		return "Satellite-data Acquisition System 3";
	case 1502:
		return "Shiva";
	case 1503:
		return "Databeam";
	case 1504:
		return "EVB Software Engineering License Manager";
	case 1505:
		return "Funk Software";
	case 1506:
		return "Universal Time daemon (utcd)";
	case 1507:
		return "symplex";
	case 1508:
		return "diagmond";
	case 1509:
		return "Robcad";
	case 1510:
		return "Midland Valley Exploration Ltd. Lic. Man.";
	case 1511:
		return "3l-l1";
	case 1512:
		return "Microsoft's Windows Internet Name Service";
	case 1513:
		return "Fujitsu Systems Business of America";
	case 1514:
		return "Fujitsu Systems Business of America";
	case 1515:
		return "ifor-protocol";
	case 1516:
		return "Virtual Places Audio data";
	case 1517:
		return "Virtual Places Audio control";
	case 1518:
		return "Virtual Places Video data";
	case 1519:
		return "Virtual Places Video control";
	case 1520:
		return "atm zip office";
	case 1521:
		return "nCube License Manager";
	case 1522:
		return "Ricardo North America License Manager";
	case 1523:
		return "cichild";
	case 1524:
		return "ingres";
	case 1525:
		return "oracle";
	case 1526:
		return "Prospero Data Access Prot non-priv";
	case 1527:
		return "oracle";
	case 1528:
		return "Not Only a Routeing Protocol";
	case 1529:
		return "oracle";
	case 1530:
		return "rap-service";
	case 1531:
		return "rap-listen";
	case 1532:
		return "miroconnect";
	case 1533:
		return "Virtual Places Software";
	case 1534:
		return "micromuse-lm";
	case 1535:
		return "ampr-info";
	case 1536:
		return "ampr-inter";
	case 1537:
		return "isi-lm";
	case 1538:
		return "3ds-lm";
	case 1539:
		return "Intellistor License Manager";
	case 1540:
		return "rds";
	case 1541:
		return "rds2";
	case 1542:
		return "gridgen-elmd";
	case 1543:
		return "simba-cs";
	case 1544:
		return "aspeclmd";
	case 1545:
		return "vistium-share";
	case 1546:
		return "abbaccuray";
	case 1547:
		return "laplink";
	case 1548:
		return "Axon License Manager";
	case 1549:
		return "Shiva Hose";
	case 1550:
		return "Image Storage license manager 3M Company";
	case 1551:
		return "HECMTL-DB";
	case 1552:
		return "pciarray";
	case 1553:
		return "sna-cs";
	case 1554:
		return "CACI Products Company License Manager";
	case 1555:
		return "livelan";
	case 1556:
		return "VERITAS Private Branch Exchange IANA assigned this well-formed service name as a replacement for veritas_pbx.";
	case 1557:
		return "ArborText License Manager";
	case 1558:
		return "xingmpeg";
	case 1559:
		return "web2host";
	case 1560:
		return "ASCI-RemoteSHADOW";
	case 1561:
		return "facilityview";
	case 1562:
		return "pconnectmgr";
	case 1563:
		return "Cadabra License Manager";
	case 1564:
		return "Pay-Per-View";
	case 1565:
		return "WinDD";
	case 1566:
		return "CORELVIDEO";
	case 1567:
		return "jlicelmd";
	case 1568:
		return "tsspmap";
	case 1569:
		return "ets";
	case 1570:
		return "orbixd";
	case 1571:
		return "Oracle Remote Data Base";
	case 1572:
		return "Chipcom License Manager";
	case 1573:
		return "itscomm-ns";
	case 1574:
		return "mvel-lm";
	case 1575:
		return "oraclenames";
	case 1576:
		return "Moldflow License Manager";
	case 1577:
		return "hypercube-lm";
	case 1578:
		return "Jacobus License Manager";
	case 1579:
		return "ioc-sea-lm";
	case 1580:
		return "tn-tl-r1";
	case 1581:
		return "MIL-2045-47001";
	case 1582:
		return "MSIMS";
	case 1583:
		return "simbaexpress";
	case 1584:
		return "tn-tl-fd2";
	case 1585:
		return "intv";
	case 1586:
		return "ibm-abtact";
	case 1587:
		return "pra_elmd IANA assigned this well-formed service name as a replacement for pra_elmd.";
	case 1588:
		return "triquest-lm";
	case 1589:
		return "VQP";
	case 1590:
		return "gemini-lm";
	case 1591:
		return "ncpm-pm";
	case 1592:
		return "commonspace";
	case 1593:
		return "mainsoft-lm";
	case 1594:
		return "sixtrak";
	case 1595:
		return "radio";
	case 1596:
		return "radio-sm";
	case 1597:
		return "orbplus-iiop";
	case 1598:
		return "picknfs";
	case 1599:
		return "simbaservices";
	case 1600:
		return "issd";
	case 1601:
		return "aas";
	case 1602:
		return "inspect";
	case 1603:
		return "pickodbc";
	case 1604:
		return "icabrowser";
	case 1605:
		return "Salutation Manager (Salutation Protocol)";
	case 1606:
		return "Salutation Manager (SLM-API)";
	case 1607:
		return "stt";
	case 1608:
		return "Smart Corp. License Manager";
	case 1609:
		return "isysg-lm";
	case 1610:
		return "taurus-wh";
	case 1611:
		return "Inter Library Loan";
	case 1612:
		return "NetBill Transaction Server";
	case 1613:
		return "NetBill Key Repository";
	case 1614:
		return "NetBill Credential Server";
	case 1615:
		return "NetBill Authorization Server";
	case 1616:
		return "NetBill Product Server";
	case 1617:
		return "Nimrod Inter-Agent Communication";
	case 1618:
		return "skytelnet";
	case 1619:
		return "xs-openstorage";
	case 1620:
		return "faxportwinport";
	case 1621:
		return "softdataphone";
	case 1622:
		return "ontime";
	case 1623:
		return "jaleosnd";
	case 1624:
		return "udp-sr-port";
	case 1625:
		return "svs-omagent";
	case 1626:
		return "Shockwave";
	case 1627:
		return "T.128 Gateway";
	case 1628:
		return "LonTalk normal";
	case 1629:
		return "LonTalk urgent";
	case 1630:
		return "Oracle Net8 Cman";
	case 1631:
		return "Visit view";
	case 1632:
		return "PAMMRATC";
	case 1633:
		return "PAMMRPC";
	case 1634:
		return "Log On America Probe";
	case 1635:
		return "EDB Server 1";
	case 1636:
		return "ISP shared public data control";
	case 1637:
		return "ISP shared local data control";
	case 1638:
		return "ISP shared management control";
	case 1639:
		return "cert-initiator";
	case 1640:
		return "cert-responder";
	case 1641:
		return "InVision";
	case 1642:
		return "isis-am";
	case 1643:
		return "isis-ambc";
	case 1644:
		return "Satellite-data Acquisition System 4";
	case 1645:
		return "SightLine";
	case 1646:
		return "sa-msg-port";
	case 1647:
		return "rsap";
	case 1648:
		return "concurrent-lm";
	case 1649:
		return "kermit";
	case 1650:
		return "nkdn";
	case 1651:
		return "shiva_confsrvr IANA assigned this well-formed service name as a replacement for shiva_confsrvr.";
	case 1652:
		return "xnmp";
	case 1653:
		return "alphatech-lm";
	case 1654:
		return "stargatealerts";
	case 1655:
		return "dec-mbadmin";
	case 1656:
		return "dec-mbadmin-h";
	case 1657:
		return "fujitsu-mmpdc";
	case 1658:
		return "sixnetudr";
	case 1659:
		return "Silicon Grail License Manager";
	case 1660:
		return "skip-mc-gikreq";
	case 1661:
		return "netview-aix-1";
	case 1662:
		return "netview-aix-2";
	case 1663:
		return "netview-aix-3";
	case 1664:
		return "netview-aix-4";
	case 1665:
		return "netview-aix-5";
	case 1666:
		return "netview-aix-6";
	case 1667:
		return "netview-aix-7";
	case 1668:
		return "netview-aix-8";
	case 1669:
		return "netview-aix-9";
	case 1670:
		return "netview-aix-10";
	case 1671:
		return "netview-aix-11";
	case 1672:
		return "netview-aix-12";
	case 1673:
		return "Intel Proshare Multicast";
	case 1674:
		return "Intel Proshare Multicast";
	case 1675:
		return "Pacific Data Products";
	case 1676:
		return "netcomm1";
	case 1677:
		return "groupwise";
	case 1678:
		return "prolink";
	case 1679:
		return "darcorp-lm";
	case 1680:
		return "microcom-sbp";
	case 1681:
		return "sd-elmd";
	case 1682:
		return "lanyon-lantern";
	case 1683:
		return "ncpm-hip";
	case 1684:
		return "SnareSecure";
	case 1685:
		return "n2nremote";
	case 1686:
		return "cvmon";
	case 1687:
		return "nsjtp-ctrl";
	case 1688:
		return "nsjtp-data";
	case 1689:
		return "firefox";
	case 1690:
		return "ng-umds";
	case 1691:
		return "empire-empuma";
	case 1692:
		return "sstsys-lm";
	case 1693:
		return "rrirtr";
	case 1694:
		return "rrimwm";
	case 1695:
		return "rrilwm";
	case 1696:
		return "rrifmm";
	case 1697:
		return "rrisat";
	case 1698:
		return "RSVP-ENCAPSULATION-1";
	case 1699:
		return "RSVP-ENCAPSULATION-2";
	case 1700:
		return "mps-raft";
	case 1701:
		return "l2f";
	case 1702:
		return "deskshare";
	case 1703:
		return "hb-engine";
	case 1704:
		return "bcs-broker";
	case 1705:
		return "slingshot";
	case 1706:
		return "jetform";
	case 1707:
		return "vdmplay";
	case 1708:
		return "gat-lmd";
	case 1709:
		return "centra";
	case 1710:
		return "impera";
	case 1711:
		return "pptconference";
	case 1712:
		return "resource monitoring service";
	case 1713:
		return "ConferenceTalk";
	case 1714:
		return "sesi-lm";
	case 1715:
		return "houdini-lm";
	case 1716:
		return "xmsg";
	case 1717:
		return "fj-hdnet";
	case 1718:
		return "H.323 Multicast Gatekeeper Discover";
	case 1719:
		return "H.323 Unicast Gatekeeper Signaling";
	case 1720:
		return "H.323 Call Control Signalling";
	case 1721:
		return "caicci";
	case 1722:
		return "HKS License Manager";
	case 1723:
		return "pptp";
	case 1724:
		return "csbphonemaster";
	case 1725:
		return "iden-ralp";
	case 1726:
		return "IBERIAGAMES";
	case 1727:
		return "winddx";
	case 1728:
		return "TELINDUS";
	case 1729:
		return "CityNL License Management";
	case 1730:
		return "roketz";
	case 1731:
		return "MSICCP";
	case 1732:
		return "proxim";
	case 1733:
		return "SIMS - SIIPAT Protocol for Alarm Transmission";
	case 1734:
		return "Camber Corporation License Management";
	case 1735:
		return "PrivateChat";
	case 1736:
		return "street-stream";
	case 1737:
		return "ultimad";
	case 1738:
		return "GameGen1";
	case 1739:
		return "webaccess";
	case 1740:
		return "encore";
	case 1741:
		return "cisco-net-mgmt";
	case 1742:
		return "3Com-nsd";
	case 1743:
		return "Cinema Graphics License Manager";
	case 1744:
		return "ncpm-ft";
	case 1745:
		return "remote-winsock";
	case 1746:
		return "ftrapid-1";
	case 1747:
		return "ftrapid-2";
	case 1748:
		return "oracle-em1";
	case 1749:
		return "aspen-services";
	case 1750:
		return "Simple Socket Library's PortMaster";
	case 1751:
		return "SwiftNet";
	case 1752:
		return "Leap of Faith Research License Manager";
	case 1753:
		return "Predatar Comms Service";
	case 1754:
		return "oracle-em2";
	case 1755:
		return "ms-streaming";
	case 1756:
		return "capfast-lmd";
	case 1757:
		return "cnhrp";
	case 1758:
		return "tftp-mcast";
	case 1759:
		return "SPSS License Manager";
	case 1760:
		return "www-ldap-gw";
	case 1761:
		return "cft-0";
	case 1762:
		return "cft-1";
	case 1763:
		return "cft-2";
	case 1764:
		return "cft-3";
	case 1765:
		return "cft-4";
	case 1766:
		return "cft-5";
	case 1767:
		return "cft-6";
	case 1768:
		return "cft-7";
	case 1769:
		return "bmc-net-adm";
	case 1770:
		return "bmc-net-svc";
	case 1771:
		return "vaultbase";
	case 1772:
		return "EssWeb Gateway";
	case 1773:
		return "KMSControl";
	case 1774:
		return "global-dtserv";
	case 1775:
		return "data interchange between visual processing containers";
	case 1776:
		return "Federal Emergency Management Information System";
	case 1777:
		return "powerguardian";
	case 1778:
		return "prodigy-internet";
	case 1779:
		return "pharmasoft";
	case 1780:
		return "dpkeyserv";
	case 1781:
		return "answersoft-lm";
	case 1782:
		return "hp-hcip";
	case 1784:
		return "Finle License Manager";
	case 1785:
		return "Wind River Systems License Manager";
	case 1786:
		return "funk-logger";
	case 1787:
		return "funk-license";
	case 1788:
		return "psmond";
	case 1789:
		return "hello";
	case 1790:
		return "Narrative Media Streaming Protocol";
	case 1791:
		return "EA1";
	case 1792:
		return "ibm-dt-2";
	case 1793:
		return "rsc-robot";
	case 1794:
		return "cera-bcm";
	case 1795:
		return "dpi-proxy";
	case 1796:
		return "Vocaltec Server Administration";
	case 1797:
		return "UMA";
	case 1798:
		return "Event Transfer Protocol";
	case 1799:
		return "NETRISK";
	case 1800:
		return "ANSYS-License manager";
	case 1801:
		return "Microsoft Message Que";
	case 1802:
		return "ConComp1";
	case 1803:
		return "HP-HCIP-GWY";
	case 1804:
		return "ENL";
	case 1805:
		return "ENL-Name";
	case 1806:
		return "Musiconline";
	case 1807:
		return "Fujitsu Hot Standby Protocol";
	case 1808:
		return "Oracle-VP2";
	case 1809:
		return "Oracle-VP1";
	case 1810:
		return "Jerand License Manager";
	case 1811:
		return "Scientia-SDB";
	case 1812:
		return "RADIUS";
	case 1813:
		return "RADIUS Accounting";
	case 1814:
		return "TDP Suite";
	case 1815:
		return "MMPFT";
	case 1816:
		return "HARP";
	case 1817:
		return "RKB-OSCS";
	case 1818:
		return "Enhanced Trivial File Transfer Protocol";
	case 1819:
		return "Plato License Manager";
	case 1820:
		return "mcagent";
	case 1821:
		return "donnyworld";
	case 1822:
		return "es-elmd";
	case 1823:
		return "Unisys Natural Language License Manager";
	case 1824:
		return "metrics-pas";
	case 1825:
		return "DirecPC Video";
	case 1826:
		return "ARDT";
	case 1827:
		return "ASI";
	case 1828:
		return "itm-mcell-u";
	case 1829:
		return "Optika eMedia";
	case 1830:
		return "Oracle Net8 CMan Admin";
	case 1831:
		return "Myrtle";
	case 1832:
		return "ThoughtTreasure";
	case 1833:
		return "udpradio";
	case 1834:
		return "ARDUS Unicast";
	case 1835:
		return "ARDUS Multicast";
	case 1836:
		return "ste-smsc";
	case 1837:
		return "csoft1";
	case 1838:
		return "TALNET";
	case 1839:
		return "netopia-vo1";
	case 1840:
		return "netopia-vo2";
	case 1841:
		return "netopia-vo3";
	case 1842:
		return "netopia-vo4";
	case 1843:
		return "netopia-vo5";
	case 1844:
		return "DirecPC-DLL";
	case 1845:
		return "altalink";
	case 1846:
		return "Tunstall PNC";
	case 1847:
		return "SLP Notification";
	case 1848:
		return "fjdocdist";
	case 1849:
		return "ALPHA-SMS";
	case 1850:
		return "GSI";
	case 1851:
		return "ctcd";
	case 1852:
		return "Virtual Time";
	case 1853:
		return "VIDS-AVTP";
	case 1854:
		return "Buddy Draw";
	case 1855:
		return "Fiorano RtrSvc";
	case 1856:
		return "Fiorano MsgSvc";
	case 1857:
		return "DataCaptor";
	case 1858:
		return "PrivateArk";
	case 1859:
		return "Gamma Fetcher Server";
	case 1860:
		return "SunSCALAR Services";
	case 1861:
		return "LeCroy VICP";
	case 1862:
		return "MySQL Cluster Manager Agent";
	case 1863:
		return "MSNP";
	case 1864:
		return "Paradym 31 Port";
	case 1865:
		return "ENTP";
	case 1866:
		return "swrmi";
	case 1867:
		return "UDRIVE";
	case 1868:
		return "VizibleBrowser";
	case 1869:
		return "TransAct";
	case 1870:
		return "SunSCALAR DNS Service";
	case 1871:
		return "Cano Central 0";
	case 1872:
		return "Cano Central 1";
	case 1873:
		return "Fjmpjps";
	case 1874:
		return "Fjswapsnp";
	case 1875:
		return "westell stats";
	case 1876:
		return "ewcappsrv";
	case 1877:
		return "hp-webqosdb";
	case 1878:
		return "drmsmc";
	case 1879:
		return "NettGain NMS";
	case 1880:
		return "Gilat VSAT Control";
	case 1881:
		return "IBM WebSphere MQ Everyplace";
	case 1882:
		return "CA eTrust Common Services";
	case 1883:
		return "Message Queuing Telemetry Transport Protocol";
	case 1884:
		return "Internet Distance Map Svc";
	case 1885:
		return "Veritas Trap Server";
	case 1886:
		return "Leonardo over IP";
	case 1887:
		return "FileX Listening Port";
	case 1888:
		return "NC Config Port";
	case 1889:
		return "Unify Web Adapter Service";
	case 1890:
		return "wilkenListener";
	case 1891:
		return "ChildKey Notification";
	case 1892:
		return "ChildKey Control";
	case 1893:
		return "ELAD Protocol";
	case 1894:
		return "O2Server Port";
	case 1895:
		return "unassigned";
	case 1896:
		return "b-novative license server";
	case 1897:
		return "MetaAgent";
	case 1898:
		return "Cymtec secure management";
	case 1899:
		return "MC2Studios";
	case 1900:
		return "SSDP";
	case 1901:
		return "Fujitsu ICL Terminal Emulator Program A";
	case 1902:
		return "Fujitsu ICL Terminal Emulator Program B";
	case 1903:
		return "Local Link Name Resolution";
	case 1904:
		return "Fujitsu ICL Terminal Emulator Program C";
	case 1905:
		return "Secure UP.Link Gateway Protocol";
	case 1906:
		return "TPortMapperReq";
	case 1907:
		return "IntraSTAR";
	case 1908:
		return "Dawn";
	case 1909:
		return "Global World Link";
	case 1910:
		return "UltraBac Software communications port";
	case 1911:
		return "Starlight Networks Multimedia Transport Protocol";
	case 1912:
		return "rhp-iibp";
	case 1913:
		return "armadp";
	case 1914:
		return "Elm-Momentum";
	case 1915:
		return "FACELINK";
	case 1916:
		return "Persoft Persona";
	case 1917:
		return "nOAgent";
	case 1918:
		return "IBM Tivole Directory Service - NDS";
	case 1919:
		return "IBM Tivoli Directory Service - DCH";
	case 1920:
		return "IBM Tivoli Directory Service - FERRET";
	case 1921:
		return "NoAdmin";
	case 1922:
		return "Tapestry";
	case 1923:
		return "SPICE";
	case 1924:
		return "XIIP";
	case 1925:
		return "Surrogate Discovery Port";
	case 1926:
		return "Evolution Game Server";
	case 1927:
		return "Videte CIPC Port";
	case 1928:
		return "Expnd Maui Srvr Dscovr";
	case 1929:
		return "Bandwiz System - Server";
	case 1930:
		return "Drive AppServer";
	case 1931:
		return "AMD SCHED";
	case 1932:
		return "CTT Broker";
	case 1933:
		return "IBM LM MT Agent";
	case 1934:
		return "IBM LM Appl Agent";
	case 1935:
		return "Macromedia Flash Communications Server MX";
	case 1936:
		return "JetCmeServer Server Port";
	case 1937:
		return "JetVWay Server Port";
	case 1938:
		return "JetVWay Client Port";
	case 1939:
		return "JetVision Server Port";
	case 1940:
		return "JetVision Client Port";
	case 1941:
		return "DIC-Aida";
	case 1942:
		return "Real Enterprise Service";
	case 1943:
		return "Beeyond Media";
	case 1944:
		return "close-combat";
	case 1945:
		return "dialogic-elmd";
	case 1946:
		return "tekpls";
	case 1947:
		return "SentinelSRM";
	case 1948:
		return "eye2eye";
	case 1949:
		return "ISMA Easdaq Live";
	case 1950:
		return "ISMA Easdaq Test";
	case 1951:
		return "bcs-lmserver";
	case 1952:
		return "mpnjsc";
	case 1953:
		return "Rapid Base";
	case 1954:
		return "ABR-API (diskbridge)";
	case 1955:
		return "ABR-Secure Data (diskbridge)";
	case 1956:
		return "Vertel VMF DS";
	case 1957:
		return "unix-status";
	case 1958:
		return "CA Administration Daemon";
	case 1959:
		return "SIMP Channel";
	case 1960:
		return "Merit DAC NASmanager";
	case 1961:
		return "BTS APPSERVER";
	case 1962:
		return "BIAP-MP";
	case 1963:
		return "WebMachine";
	case 1964:
		return "SOLID E ENGINE";
	case 1965:
		return "Tivoli NPM";
	case 1966:
		return "Slush";
	case 1967:
		return "SNS Quote";
	case 1968:
		return "LIPSinc";
	case 1969:
		return "LIPSinc 1";
	case 1970:
		return "NetOp Remote Control";
	case 1971:
		return "NetOp School";
	case 1972:
		return "Cache";
	case 1973:
		return "Data Link Switching Remote Access Protocol";
	case 1974:
		return "DRP";
	case 1975:
		return "TCO Flash Agent";
	case 1976:
		return "TCO Reg Agent";
	case 1977:
		return "TCO Address Book";
	case 1978:
		return "UniSQL";
	case 1979:
		return "UniSQL Java";
	case 1980:
		return "PearlDoc XACT";
	case 1981:
		return "p2pQ";
	case 1982:
		return "Evidentiary Timestamp";
	case 1983:
		return "Loophole Test Protocol";
	case 1984:
		return "BB";
	case 1985:
		return "Hot Standby Router Protocol";
	case 1986:
		return "cisco license management";
	case 1987:
		return "cisco RSRB Priority 1 port";
	case 1988:
		return "cisco RSRB Priority 2 port";
	case 1989:
		return "cisco RSRB Priority 3 port";
	case 1990:
		return "cisco STUN Priority 1 port";
	case 1991:
		return "cisco STUN Priority 2 port";
	case 1992:
		return "cisco STUN Priority 3 port";
	case 1993:
		return "cisco SNMP TCP port";
	case 1994:
		return "cisco serial tunnel port";
	case 1995:
		return "cisco perf port";
	case 1996:
		return "cisco Remote SRB port";
	case 1997:
		return "cisco Gateway Discovery Protocol";
	case 1998:
		return "cisco X.25 service (XOT)";
	case 1999:
		return "cisco identification port";
	case 2000:
		return "Cisco SCCP";
	case 2001:
		return "";
	case 2002:
		return "";
	case 2003:
		return "Brutus Server";
	case 2004:
		return "";
	case 2005:
		return "";
	case 2006:
		return "";
	case 2007:
		return "";
	case 2008:
		return "";
	case 2009:
		return "";
	case 2010:
		return "";
	case 2011:
		return "raid";
	case 2012:
		return "";
	case 2013:
		return "";
	case 2014:
		return "";
	case 2015:
		return "";
	case 2016:
		return "";
	case 2017:
		return "";
	case 2018:
		return "";
	case 2019:
		return "";
	case 2020:
		return "";
	case 2021:
		return "";
	case 2022:
		return "";
	case 2023:
		return "";
	case 2024:
		return "";
	case 2025:
		return "";
	case 2026:
		return "";
	case 2027:
		return "";
	case 2028:
		return "";
	case 2029:
		return "Hot Standby Router Protocol IPv6";
	case 2030:
		return "";
	case 2031:
		return "mobrien-chat";
	case 2032:
		return "";
	case 2033:
		return "";
	case 2034:
		return "";
	case 2035:
		return "";
	case 2036:
		return "Ethernet WS DP network";
	case 2037:
		return "APplus Application Server";
	case 2038:
		return "";
	case 2039:
		return "Prizma Monitoring Service";
	case 2040:
		return "";
	case 2041:
		return "";
	case 2042:
		return "isis";
	case 2043:
		return "isis-bcast";
	case 2044:
		return "";
	case 2045:
		return "";
	case 2046:
		return "";
	case 2047:
		return "";
	case 2048:
		return "";
	case 2049:
		return "";
	case 2050:
		return "Avaya EMB Config Port";
	case 2051:
		return "EPNSDP";
	case 2052:
		return "clearVisn Services Port";
	case 2053:
		return "Lot105 DSuper Updates";
	case 2054:
		return "Weblogin Port";
	case 2055:
		return "Iliad-Odyssey Protocol";
	case 2056:
		return "OmniSky Port";
	case 2057:
		return "Rich Content Protocol";
	case 2058:
		return "NewWaveSearchables RMI";
	case 2059:
		return "BMC Messaging Service";
	case 2060:
		return "Telenium Daemon IF";
	case 2061:
		return "NetMount";
	case 2062:
		return "ICG SWP Port";
	case 2063:
		return "ICG Bridge Port";
	case 2064:
		return "ICG IP Relay Port";
	case 2065:
		return "Data Link Switch Read Port Number";
	case 2066:
		return "AVM USB Remote Architecture";
	case 2067:
		return "Data Link Switch Write Port Number";
	case 2068:
		return "Avocent AuthSrv Protocol";
	case 2069:
		return "HTTP Event Port";
	case 2070:
		return "AH and ESP Encapsulated in UDP packet";
	case 2071:
		return "Axon Control Protocol";
	case 2072:
		return "GlobeCast mSync";
	case 2073:
		return "DataReel Database Socket";
	case 2074:
		return "Vertel VMF SA";
	case 2075:
		return "Newlix ServerWare Engine";
	case 2076:
		return "Newlix JSPConfig";
	case 2077:
		return "Old Tivoli Storage Manager";
	case 2078:
		return "IBM Total Productivity Center Server";
	case 2079:
		return "IDWARE Router Port";
	case 2080:
		return "Autodesk NLM (FLEXlm)";
	case 2081:
		return "KME PRINTER TRAP PORT";
	case 2082:
		return "Infowave Mobility Server";
	case 2083:
		return "Secure Radius Service";
	case 2084:
		return "SunCluster Geographic";
	case 2085:
		return "ADA Control";
	case 2086:
		return "GNUnet";
	case 2087:
		return "ELI - Event Logging Integration";
	case 2088:
		return "IP Busy Lamp Field";
	case 2089:
		return "Security Encapsulation Protocol - SEP";
	case 2090:
		return "Load Report Protocol";
	case 2091:
		return "PRP";
	case 2092:
		return "Descent 3";
	case 2093:
		return "NBX CC";
	case 2094:
		return "NBX AU";
	case 2095:
		return "NBX SER";
	case 2096:
		return "NBX DIR";
	case 2097:
		return "Jet Form Preview";
	case 2098:
		return "Dialog Port";
	case 2099:
		return "H.225.0 Annex G Signalling";
	case 2100:
		return "Amiga Network Filesystem";
	case 2101:
		return "rtcm-sc104";
	case 2102:
		return "Zephyr server";
	case 2103:
		return "Zephyr serv-hm connection";
	case 2104:
		return "Zephyr hostmanager";
	case 2105:
		return "MiniPay";
	case 2106:
		return "MZAP";
	case 2107:
		return "BinTec Admin";
	case 2108:
		return "Comcam";
	case 2109:
		return "Ergolight";
	case 2110:
		return "UMSP";
	case 2111:
		return "OPNET Dynamic Sampling Agent Transaction Protocol";
	case 2112:
		return "Idonix MetaNet";
	case 2113:
		return "HSL StoRM";
	case 2114:
		return "Classical Music Meta-Data Access and Enhancement";
	case 2115:
		return "Key Distribution Manager";
	case 2116:
		return "CCOWCMR";
	case 2117:
		return "MENTACLIENT";
	case 2118:
		return "MENTASERVER";
	case 2119:
		return "GSIGATEKEEPER";
	case 2120:
		return "Quick Eagle Networks CP";
	case 2121:
		return "SCIENTIA-SSDB";
	case 2122:
		return "CauPC Remote Control";
	case 2123:
		return "GTP-Control Plane (3GPP)";
	case 2124:
		return "ELATELINK";
	case 2125:
		return "LOCKSTEP";
	case 2126:
		return "PktCable-COPS";
	case 2127:
		return "INDEX-PC-WB";
	case 2128:
		return "Net Steward Control";
	case 2129:
		return "cs-live.com";
	case 2130:
		return "XDS";
	case 2131:
		return "Avantageb2b";
	case 2132:
		return "SoleraTec End Point Map";
	case 2133:
		return "ZYMED-ZPP";
	case 2134:
		return "AVENUE";
	case 2135:
		return "Grid Resource Information Server";
	case 2136:
		return "APPWORXSRV";
	case 2137:
		return "CONNECT";
	case 2138:
		return "UNBIND-CLUSTER";
	case 2139:
		return "IAS-AUTH";
	case 2140:
		return "IAS-REG";
	case 2141:
		return "IAS-ADMIND";
	case 2142:
		return "TDM OVER IP";
	case 2143:
		return "Live Vault Job Control";
	case 2144:
		return "Live Vault Fast Object Transfer";
	case 2145:
		return "Live Vault Remote Diagnostic Console Support";
	case 2146:
		return "Live Vault Admin Event Notification";
	case 2147:
		return "Live Vault Authentication";
	case 2148:
		return "VERITAS UNIVERSAL COMMUNICATION LAYER";
	case 2149:
		return "ACPTSYS";
	case 2150:
		return "DYNAMIC3D";
	case 2151:
		return "DOCENT";
	case 2152:
		return "GTP-User Plane (3GPP)";
	case 2153:
		return "Control Protocol";
	case 2154:
		return "Standard Protocol";
	case 2155:
		return "Bridge Protocol";
	case 2156:
		return "Talari Reliable Protocol";
	case 2157:
		return "Xerox Network Document Scan Protocol";
	case 2158:
		return "TouchNetPlus Service";
	case 2159:
		return "GDB Remote Debug Port";
	case 2160:
		return "APC 2160";
	case 2161:
		return "APC 2161";
	case 2162:
		return "Navisphere";
	case 2163:
		return "Navisphere Secure";
	case 2164:
		return "Dynamic DNS Version 3";
	case 2165:
		return "X-Bone API";
	case 2166:
		return "iwserver";
	case 2167:
		return "Raw Async Serial Link";
	case 2168:
		return "easy-soft Multiplexer";
	case 2169:
		return "Backbone for Academic Information Notification (BRAIN)";
	case 2170:
		return "EyeTV Server Port";
	case 2171:
		return "MS Firewall Storage";
	case 2172:
		return "MS Firewall SecureStorage";
	case 2173:
		return "MS Firewall Replication";
	case 2174:
		return "MS Firewall Intra Array";
	case 2175:
		return "Microsoft Desktop AirSync Protocol";
	case 2176:
		return "Microsoft ActiveSync Remote API";
	case 2177:
		return "qWAVE Bandwidth Estimate";
	case 2178:
		return "Peer Services for BITS";
	case 2179:
		return "Microsoft RDP for virtual machines";
	case 2180:
		return "Millicent Vendor Gateway Server";
	case 2181:
		return "eforward";
	case 2182:
		return "CGN status";
	case 2183:
		return "Code Green configuration";
	case 2184:
		return "NVD User";
	case 2185:
		return "OnBase Distributed Disk Services";
	case 2186:
		return "Guy-Tek Automated Update Applications";
	case 2187:
		return "Sepehr System Management Control";
	case 2188:
		return "Radware Resource Pool Manager";
	case 2189:
		return "Secure Radware Resource Pool Manager";
	case 2190:
		return "TiVoConnect Beacon";
	case 2191:
		return "TvBus Messaging";
	case 2192:
		return "ASDIS software management";
	case 2193:
		return "Dr.Web Enterprise Management Service";
	case 2197:
		return "MNP data exchange";
	case 2198:
		return "OneHome Remote Access";
	case 2199:
		return "OneHome Service Port";
	case 2200:
		return "Reserved";
	case 2201:
		return "Advanced Training System Program";
	case 2202:
		return "Int. Multimedia Teleconferencing Cosortium";
	case 2203:
		return "b2 Runtime Protocol";
	case 2204:
		return "b2 License Server";
	case 2205:
		return "Java Presentation Server";
	case 2206:
		return "HP OpenCall bus";
	case 2207:
		return "HP Status and Services";
	case 2208:
		return "HP I/O Backend";
	case 2209:
		return "HP RIM for Files Portal Service";
	case 2210:
		return "NOAAPORT Broadcast Network";
	case 2211:
		return "EMWIN";
	case 2212:
		return "LeeCO POS Server Service";
	case 2213:
		return "Kali";
	case 2214:
		return "RDQ Protocol Interface";
	case 2215:
		return "IPCore.co.za GPRS";
	case 2216:
		return "VTU data service";
	case 2217:
		return "GoToDevice Device Management";
	case 2218:
		return "Bounzza IRC Proxy";
	case 2219:
		return "NetIQ NCAP Protocol";
	case 2220:
		return "NetIQ End2End";
	case 2221:
		return "EtherNet/IP over TLS";
	case 2222:
		return "EtherNet/IP I/O IANA assigned this well-formed service name as a replacement for EtherNet/IP-1.";
	case 2223:
		return "Rockwell CSP2";
	case 2224:
		return "Easy Flexible Internet/Multiplayer Games";
	case 2225:
		return "Resource Connection Initiation Protocol";
	case 2226:
		return "Digital Instinct DRM";
	case 2227:
		return "DI Messaging Service";
	case 2228:
		return "eHome Message Server";
	case 2229:
		return "DataLens Service";
	case 2230:
		return "MetaSoft Job Queue Administration Service";
	case 2231:
		return "WiMAX ASN Control Plane Protocol";
	case 2232:
		return "IVS Video default";
	case 2233:
		return "INFOCRYPT";
	case 2234:
		return "DirectPlay";
	case 2235:
		return "Sercomm-WLink";
	case 2236:
		return "Nani";
	case 2237:
		return "Optech Port1 License Manager";
	case 2238:
		return "AVIVA SNA SERVER";
	case 2239:
		return "Image Query";
	case 2240:
		return "RECIPe";
	case 2241:
		return "IVS Daemon";
	case 2242:
		return "Folio Remote Server";
	case 2243:
		return "Magicom Protocol";
	case 2244:
		return "NMS Server";
	case 2245:
		return "HaO";
	case 2246:
		return "PacketCable MTA Addr Map";
	case 2247:
		return "Antidote Deployment Manager Service";
	case 2248:
		return "User Management Service";
	case 2249:
		return "RISO File Manager Protocol";
	case 2250:
		return "remote-collab";
	case 2251:
		return "Distributed Framework Port";
	case 2252:
		return "NJENET using SSL";
	case 2253:
		return "DTV Channel Request";
	case 2254:
		return "Seismic P.O.C. Port";
	case 2255:
		return "VRTP - ViRtue Transfer Protocol";
	case 2256:
		return "PCC MFP";
	case 2257:
		return "simple text/file transfer";
	case 2258:
		return "Rotorcraft Communications Test System";
	case 2259:
		return "BIF identifiers resolution service";
	case 2260:
		return "APC 2260";
	case 2261:
		return "CoMotion Master Server";
	case 2262:
		return "CoMotion Backup Server";
	case 2263:
		return "ECweb Configuration Service";
	case 2264:
		return "Audio Precision Apx500 API Port 1";
	case 2265:
		return "Audio Precision Apx500 API Port 2";
	case 2266:
		return "M-Files Server";
	case 2267:
		return "OntoBroker";
	case 2268:
		return "AMT";
	case 2269:
		return "MIKEY";
	case 2270:
		return "starSchool";
	case 2271:
		return "Secure Meeting Maker Scheduling";
	case 2272:
		return "Meeting Maker Scheduling";
	case 2273:
		return "MySQL Instance Manager";
	case 2274:
		return "PCTTunneller";
	case 2275:
		return "iBridge Conferencing";
	case 2276:
		return "iBridge Management";
	case 2277:
		return "Bt device control proxy";
	case 2278:
		return "Simple Stacked Sequences Database";
	case 2279:
		return "xmquery";
	case 2280:
		return "LNVPOLLER";
	case 2281:
		return "LNVCONSOLE";
	case 2282:
		return "LNVALARM";
	case 2283:
		return "LNVSTATUS";
	case 2284:
		return "LNVMAPS";
	case 2285:
		return "LNVMAILMON";
	case 2286:
		return "NAS-Metering";
	case 2287:
		return "DNA";
	case 2288:
		return "NETML";
	case 2289:
		return "Lookup dict server";
	case 2290:
		return "Sonus Logging Services";
	case 2291:
		return "EPSON Advanced Printer Share Protocol";
	case 2292:
		return "Sonus Element Management Services";
	case 2293:
		return "Network Platform Debug Manager";
	case 2294:
		return "Konshus License Manager (FLEX)";
	case 2295:
		return "Advant License Manager";
	case 2296:
		return "Theta License Manager (Rainbow)";
	case 2297:
		return "D2K DataMover 1";
	case 2298:
		return "D2K DataMover 2";
	case 2299:
		return "PC Telecommute";
	case 2300:
		return "CVMMON";
	case 2301:
		return "Compaq HTTP";
	case 2302:
		return "Bindery Support";
	case 2303:
		return "Proxy Gateway";
	case 2304:
		return "Attachmate UTS";
	case 2305:
		return "MT ScaleServer";
	case 2306:
		return "TAPPI BoxNet";
	case 2307:
		return "pehelp";
	case 2308:
		return "sdhelp";
	case 2309:
		return "SD Server";
	case 2310:
		return "SD Client";
	case 2311:
		return "Message Service";
	case 2312:
		return "WANScaler Communication Service";
	case 2313:
		return "IAPP (Inter Access Point Protocol)";
	case 2314:
		return "CR WebSystems";
	case 2315:
		return "Precise Sft.";
	case 2316:
		return "SENT License Manager";
	case 2317:
		return "Attachmate G32";
	case 2318:
		return "Cadence Control";
	case 2319:
		return "InfoLibria";
	case 2320:
		return "Siebel NS";
	case 2321:
		return "RDLAP";
	case 2322:
		return "ofsd";
	case 2323:
		return "3d-nfsd";
	case 2324:
		return "Cosmocall";
	case 2325:
		return "ANSYS Licensing Interconnect";
	case 2326:
		return "IDCP";
	case 2327:
		return "xingcsm";
	case 2328:
		return "Netrix SFTM";
	case 2329:
		return "NVD";
	case 2330:
		return "TSCCHAT";
	case 2331:
		return "AGENTVIEW";
	case 2332:
		return "RCC Host";
	case 2333:
		return "SNAPP";
	case 2334:
		return "ACE Client Auth";
	case 2335:
		return "ACE Proxy";
	case 2336:
		return "Apple UG Control";
	case 2337:
		return "ideesrv";
	case 2338:
		return "Norton Lambert";
	case 2339:
		return "3Com WebView";
	case 2340:
		return "WRS Registry IANA assigned this well-formed service name as a replacement for wrs_registry.";
	case 2341:
		return "XIO Status";
	case 2342:
		return "Seagate Manage Exec";
	case 2343:
		return "nati logos";
	case 2344:
		return "fcmsys";
	case 2345:
		return "dbm";
	case 2346:
		return "Game Connection Port IANA assigned this well-formed service name as a replacement for redstorm_join.";
	case 2347:
		return "Game Announcement and Location IANA assigned this well-formed service name as a replacement for redstorm_find.";
	case 2348:
		return "Information to query for game status IANA assigned this well-formed service name as a replacement for redstorm_info.";
	case 2349:
		return "Diagnostics Port IANA assigned this well-formed service name as a replacement for redstorm_diag.";
	case 2350:
		return "Pharos Booking Server";
	case 2351:
		return "psrserver";
	case 2352:
		return "pslserver";
	case 2353:
		return "pspserver";
	case 2354:
		return "psprserver";
	case 2355:
		return "psdbserver";
	case 2356:
		return "GXT License Managemant";
	case 2357:
		return "UniHub Server";
	case 2358:
		return "Futrix";
	case 2359:
		return "FlukeServer";
	case 2360:
		return "NexstorIndLtd";
	case 2361:
		return "TL1";
	case 2362:
		return "digiman";
	case 2363:
		return "Media Central NFSD";
	case 2364:
		return "OI-2000";
	case 2365:
		return "dbref";
	case 2366:
		return "qip-login";
	case 2367:
		return "Service Control";
	case 2368:
		return "OpenTable";
	case 2369:
		return "Blockchain Identifier InFrastructure P2P";
	case 2370:
		return "L3-HBMon";
	case 2371:
		return "Remote Device Access";
	case 2372:
		return "LanMessenger";
	case 2373:
		return "Remograph License Manager";
	case 2374:
		return "Hydra RPC";
	case 2375:
		return "Docker REST API (plain text)";
	case 2376:
		return "Docker REST API (ssl)";
	case 2377:
		return "RPC interface for Docker Swarm";
	case 2378:
		return "Reserved";
	case 2379:
		return "etcd client communication";
	case 2380:
		return "etcd server to server communication";
	case 2381:
		return "Compaq HTTPS";
	case 2382:
		return "Microsoft OLAP";
	case 2383:
		return "Microsoft OLAP";
	case 2384:
		return "SD-REQUEST";
	case 2385:
		return "SD-DATA";
	case 2386:
		return "Virtual Tape";
	case 2387:
		return "VSAM Redirector";
	case 2388:
		return "MYNAH AutoStart";
	case 2389:
		return "OpenView Session Mgr";
	case 2390:
		return "RSMTP";
	case 2391:
		return "3COM Net Management";
	case 2392:
		return "Tactical Auth";
	case 2393:
		return "MS OLAP 1";
	case 2394:
		return "MS OLAP 2";
	case 2395:
		return "LAN900 Remote IANA assigned this well-formed service name as a replacement for lan900_remote.";
	case 2396:
		return "Wusage";
	case 2397:
		return "NCL";
	case 2398:
		return "Orbiter";
	case 2399:
		return "FileMaker";
	case 2400:
		return "OpEquus Server";
	case 2401:
		return "cvspserver";
	case 2402:
		return "TaskMaster 2000 Server";
	case 2403:
		return "TaskMaster 2000 Web";
	case 2404:
		return "IEC 60870-5-104 process control over IP";
	case 2405:
		return "TRC Netpoll";
	case 2406:
		return "JediServer";
	case 2407:
		return "Orion";
	case 2408:
		return "CloudFlare Railgun Web Acceleration Protocol";
	case 2409:
		return "SNS Protocol";
	case 2410:
		return "VRTS Registry";
	case 2411:
		return "Netwave AP Management";
	case 2412:
		return "CDN";
	case 2413:
		return "orion-rmi-reg";
	case 2414:
		return "Beeyond";
	case 2415:
		return "Codima Remote Transaction Protocol";
	case 2416:
		return "RMT Server";
	case 2417:
		return "Composit Server";
	case 2418:
		return "cas";
	case 2419:
		return "Attachmate S2S";
	case 2420:
		return "DSL Remote Management";
	case 2421:
		return "G-Talk";
	case 2422:
		return "CRMSBITS";
	case 2423:
		return "RNRP";
	case 2424:
		return "KOFAX-SVR";
	case 2425:
		return "Fujitsu App Manager";
	case 2426:
		return "VeloCloud MultiPath Protocol";
	case 2427:
		return "Media Gateway Control Protocol Gateway";
	case 2428:
		return "One Way Trip Time";
	case 2429:
		return "FT-ROLE";
	case 2430:
		return "venus";
	case 2431:
		return "venus-se";
	case 2432:
		return "codasrv";
	case 2433:
		return "codasrv-se";
	case 2434:
		return "pxc-epmap";
	case 2435:
		return "OptiLogic";
	case 2436:
		return "TOP/X";
	case 2437:
		return "UniControl";
	case 2438:
		return "MSP";
	case 2439:
		return "SybaseDBSynch";
	case 2440:
		return "Spearway Lockers";
	case 2441:
		return "Pervasive I*net Data Server";
	case 2442:
		return "Netangel";
	case 2443:
		return "PowerClient Central Storage Facility";
	case 2444:
		return "BT PP2 Sectrans";
	case 2445:
		return "DTN1";
	case 2446:
		return "bues_service IANA assigned this well-formed service name as a replacement for bues_service.";
	case 2447:
		return "OpenView NNM daemon";
	case 2448:
		return "hpppsvr";
	case 2449:
		return "RATL";
	case 2450:
		return "netadmin";
	case 2451:
		return "netchat";
	case 2452:
		return "SnifferClient";
	case 2453:
		return "madge ltd";
	case 2454:
		return "IndX-DDS";
	case 2455:
		return "WAGO-IO-SYSTEM";
	case 2456:
		return "altav-remmgt";
	case 2457:
		return "Rapido_IP";
	case 2458:
		return "griffin";
	case 2459:
		return "Community";
	case 2460:
		return "ms-theater";
	case 2461:
		return "qadmifoper";
	case 2462:
		return "qadmifevent";
	case 2463:
		return "LSI RAID Management";
	case 2464:
		return "DirecPC SI";
	case 2465:
		return "Load Balance Management";
	case 2466:
		return "Load Balance Forwarding";
	case 2467:
		return "High Criteria";
	case 2468:
		return "qip_msgd";
	case 2469:
		return "MTI-TCS-COMM";
	case 2470:
		return "taskman port";
	case 2471:
		return "SeaODBC";
	case 2472:
		return "C3";
	case 2473:
		return "Aker-cdp";
	case 2474:
		return "Vital Analysis";
	case 2475:
		return "ACE Server";
	case 2476:
		return "ACE Server Propagation";
	case 2477:
		return "SecurSight Certificate Valifation Service";
	case 2478:
		return "SecurSight Authentication Server (SSL)";
	case 2479:
		return "SecurSight Event Logging Server (SSL)";
	case 2480:
		return "Informatica PowerExchange Listener";
	case 2481:
		return "Oracle GIOP";
	case 2482:
		return "Oracle GIOP SSL";
	case 2483:
		return "Oracle TTC";
	case 2484:
		return "Oracle TTC SSL";
	case 2485:
		return "Net Objects1";
	case 2486:
		return "Net Objects2";
	case 2487:
		return "Policy Notice Service";
	case 2488:
		return "Moy Corporation";
	case 2489:
		return "TSILB";
	case 2490:
		return "qip_qdhcp";
	case 2491:
		return "Conclave CPP";
	case 2492:
		return "GROOVE";
	case 2493:
		return "Talarian MQS";
	case 2494:
		return "BMC AR";
	case 2495:
		return "Fast Remote Services";
	case 2496:
		return "DIRGIS";
	case 2497:
		return "Quad DB";
	case 2498:
		return "ODN-CasTraq";
	case 2499:
		return "UniControl";
	case 2500:
		return "Resource Tracking system server";
	case 2501:
		return "Resource Tracking system client";
	case 2502:
		return "Kentrox Protocol";
	case 2503:
		return "NMS-DPNSS";
	case 2504:
		return "WLBS";
	case 2505:
		return "PowerPlay Control";
	case 2506:
		return "jbroker";
	case 2507:
		return "spock";
	case 2508:
		return "JDataStore";
	case 2509:
		return "fjmpss";
	case 2510:
		return "fjappmgrbulk";
	case 2511:
		return "Metastorm";
	case 2512:
		return "Citrix IMA";
	case 2513:
		return "Citrix ADMIN";
	case 2514:
		return "Facsys NTP";
	case 2515:
		return "Facsys Router";
	case 2516:
		return "Main Control";
	case 2517:
		return "H.323 Annex E Call Control Signalling Transport";
	case 2518:
		return "Willy";
	case 2519:
		return "globmsgsvc";
	case 2520:
		return "Pervasive Listener";
	case 2521:
		return "Adaptec Manager";
	case 2522:
		return "WinDb";
	case 2523:
		return "Qke LLC V.3";
	case 2524:
		return "Optiwave License Management";
	case 2525:
		return "MS V-Worlds";
	case 2526:
		return "EMA License Manager";
	case 2527:
		return "IQ Server";
	case 2528:
		return "NCR CCL IANA assigned this well-formed service name as a replacement for ncr_ccl.";
	case 2529:
		return "UTS FTP";
	case 2530:
		return "VR Commerce";
	case 2531:
		return "ITO-E GUI";
	case 2532:
		return "OVTOPMD";
	case 2533:
		return "SnifferServer";
	case 2534:
		return "Combox Web Access";
	case 2535:
		return "MADCAP";
	case 2536:
		return "btpp2audctr1";
	case 2537:
		return "Upgrade Protocol";
	case 2538:
		return "vnwk-prapi";
	case 2539:
		return "VSI Admin";
	case 2540:
		return "LonWorks";
	case 2541:
		return "LonWorks2";
	case 2542:
		return "uDraw(Graph)";
	case 2543:
		return "REFTEK";
	case 2544:
		return "Management Daemon Refresh";
	case 2545:
		return "sis-emt";
	case 2546:
		return "vytalvaultbrtp";
	case 2547:
		return "vytalvaultvsmp";
	case 2548:
		return "vytalvaultpipe";
	case 2549:
		return "IPASS";
	case 2550:
		return "ADS";
	case 2551:
		return "ISG UDA Server";
	case 2552:
		return "Call Logging";
	case 2553:
		return "efidiningport";
	case 2554:
		return "VCnet-Link v10";
	case 2555:
		return "Compaq WCP";
	case 2556:
		return "nicetec-nmsvc";
	case 2557:
		return "nicetec-mgmt";
	case 2558:
		return "PCLE Multi Media";
	case 2559:
		return "LSTP";
	case 2560:
		return "labrat";
	case 2561:
		return "MosaixCC";
	case 2562:
		return "Delibo";
	case 2563:
		return "CTI Redwood";
	case 2564:
		return "HP 3000 NS/VT block mode telnet";
	case 2565:
		return "Coordinator Server";
	case 2566:
		return "pcs-pcw";
	case 2567:
		return "Cisco Line Protocol";
	case 2568:
		return "SPAM TRAP";
	case 2569:
		return "Sonus Call Signal";
	case 2570:
		return "HS Port";
	case 2571:
		return "CECSVC";
	case 2572:
		return "IBP";
	case 2573:
		return "Trust Establish";
	case 2574:
		return "Blockade BPSP";
	case 2575:
		return "HL7";
	case 2576:
		return "TCL Pro Debugger";
	case 2577:
		return "Scriptics Lsrvr";
	case 2578:
		return "RVS ISDN DCP";
	case 2579:
		return "mpfoncl";
	case 2580:
		return "Tributary";
	case 2581:
		return "ARGIS TE";
	case 2582:
		return "ARGIS DS";
	case 2583:
		return "MON";
	case 2584:
		return "cyaserv";
	case 2585:
		return "NETX Server";
	case 2586:
		return "NETX Agent";
	case 2587:
		return "MASC";
	case 2588:
		return "Privilege";
	case 2589:
		return "quartus tcl";
	case 2590:
		return "idotdist";
	case 2591:
		return "Maytag Shuffle";
	case 2592:
		return "netrek";
	case 2593:
		return "MNS Mail Notice Service";
	case 2594:
		return "Data Base Server";
	case 2595:
		return "World Fusion 1";
	case 2596:
		return "World Fusion 2";
	case 2597:
		return "Homestead Glory";
	case 2598:
		return "Citrix MA Client";
	case 2599:
		return "Snap Discovery";
	case 2600:
		return "HPSTGMGR";
	case 2601:
		return "discp client";
	case 2602:
		return "discp server";
	case 2603:
		return "Service Meter";
	case 2604:
		return "NSC CCS";
	case 2605:
		return "NSC POSA";
	case 2606:
		return "Dell Netmon";
	case 2607:
		return "Dell Connection";
	case 2608:
		return "Wag Service";
	case 2609:
		return "System Monitor";
	case 2610:
		return "VersaTek";
	case 2611:
		return "LIONHEAD";
	case 2612:
		return "Qpasa Agent";
	case 2613:
		return "SMNTUBootstrap";
	case 2614:
		return "Never Offline";
	case 2615:
		return "firepower";
	case 2616:
		return "appswitch-emp";
	case 2617:
		return "Clinical Context Managers";
	case 2618:
		return "Priority E-Com";
	case 2619:
		return "bruce";
	case 2620:
		return "LPSRecommender";
	case 2621:
		return "Miles Apart Jukebox Server";
	case 2622:
		return "MetricaDBC";
	case 2623:
		return "LMDP";
	case 2624:
		return "Aria";
	case 2625:
		return "Blwnkl Port";
	case 2626:
		return "gbjd816";
	case 2627:
		return "Moshe Beeri";
	case 2628:
		return "DICT";
	case 2629:
		return "Sitara Server";
	case 2630:
		return "Sitara Management";
	case 2631:
		return "Sitara Dir";
	case 2632:
		return "IRdg Post";
	case 2633:
		return "InterIntelli";
	case 2634:
		return "PK Electronics";
	case 2635:
		return "Back Burner";
	case 2636:
		return "Solve";
	case 2637:
		return "Import Document Service";
	case 2638:
		return "Sybase Anywhere";
	case 2639:
		return "AMInet";
	case 2640:
		return "Alcorn McBride Inc protocol used for device control";
	case 2641:
		return "HDL Server";
	case 2642:
		return "Tragic";
	case 2643:
		return "GTE-SAMP";
	case 2644:
		return "Travsoft IPX Tunnel";
	case 2645:
		return "Novell IPX CMD";
	case 2646:
		return "AND License Manager";
	case 2647:
		return "SyncServer";
	case 2648:
		return "Upsnotifyprot";
	case 2649:
		return "VPSIPPORT";
	case 2650:
		return "eristwoguns";
	case 2651:
		return "EBInSite";
	case 2652:
		return "InterPathPanel";
	case 2653:
		return "Sonus";
	case 2654:
		return "Corel VNC Admin IANA assigned this well-formed service name as a replacement for corel_vncadmin.";
	case 2655:
		return "UNIX Nt Glue";
	case 2656:
		return "Kana";
	case 2657:
		return "SNS Dispatcher";
	case 2658:
		return "SNS Admin";
	case 2659:
		return "SNS Query";
	case 2660:
		return "GC Monitor";
	case 2661:
		return "OLHOST";
	case 2662:
		return "BinTec-CAPI";
	case 2663:
		return "BinTec-TAPI";
	case 2664:
		return "Patrol for MQ GM";
	case 2665:
		return "Patrol for MQ NM";
	case 2666:
		return "extensis";
	case 2667:
		return "Alarm Clock Server";
	case 2668:
		return "Alarm Clock Client";
	case 2669:
		return "TOAD";
	case 2670:
		return "TVE Announce";
	case 2671:
		return "newlixreg";
	case 2672:
		return "nhserver";
	case 2673:
		return "First Call 42";
	case 2674:
		return "ewnn";
	case 2675:
		return "TTC ETAP";
	case 2676:
		return "SIMSLink";
	case 2677:
		return "Gadget Gate 1 Way";
	case 2678:
		return "Gadget Gate 2 Way";
	case 2679:
		return "Sync Server SSL";
	case 2680:
		return "pxc-sapxom";
	case 2681:
		return "mpnjsomb";
	case 2683:
		return "NCDLoadBalance";
	case 2684:
		return "mpnjsosv";
	case 2685:
		return "mpnjsocl";
	case 2686:
		return "mpnjsomg";
	case 2687:
		return "pq-lic-mgmt";
	case 2688:
		return "md-cf-http";
	case 2689:
		return "FastLynx";
	case 2690:
		return "HP NNM Embedded Database";
	case 2691:
		return "ITInternet ISM Server";
	case 2692:
		return "Admins LMS";
	case 2693:
		return "Unassigned";
	case 2694:
		return "pwrsevent";
	case 2695:
		return "VSPREAD";
	case 2696:
		return "Unify Admin";
	case 2697:
		return "Oce SNMP Trap Port";
	case 2698:
		return "MCK-IVPIP";
	case 2699:
		return "Csoft Plus Client";
	case 2700:
		return "tqdata";
	case 2701:
		return "SMS RCINFO";
	case 2702:
		return "SMS XFER";
	case 2703:
		return "SMS CHAT";
	case 2704:
		return "SMS REMCTRL";
	case 2705:
		return "SDS Admin";
	case 2706:
		return "NCD Mirroring";
	case 2707:
		return "EMCSYMAPIPORT";
	case 2708:
		return "Banyan-Net";
	case 2709:
		return "Supermon";
	case 2710:
		return "SSO Service";
	case 2711:
		return "SSO Control";
	case 2712:
		return "Axapta Object Communication Protocol";
	case 2713:
		return "Raven Trinity Broker Service";
	case 2714:
		return "Raven Trinity Data Mover";
	case 2715:
		return "HPSTGMGR2";
	case 2716:
		return "Inova IP Disco";
	case 2717:
		return "PN REQUESTER";
	case 2718:
		return "PN REQUESTER 2";
	case 2719:
		return "Scan & Change";
	case 2720:
		return "wkars";
	case 2721:
		return "Smart Diagnose";
	case 2722:
		return "Proactive Server";
	case 2723:
		return "WatchDog NT Protocol";
	case 2724:
		return "qotps";
	case 2725:
		return "MSOLAP PTP2";
	case 2726:
		return "TAMS";
	case 2727:
		return "Media Gateway Control Protocol Call Agent";
	case 2728:
		return "SQDR";
	case 2729:
		return "TCIM Control";
	case 2730:
		return "NEC RaidPlus";
	case 2731:
		return "Fyre Messanger";
	case 2732:
		return "G5M";
	case 2733:
		return "Signet CTF";
	case 2734:
		return "CCS Software";
	case 2735:
		return "NetIQ Monitor Console";
	case 2736:
		return "RADWIZ NMS SRV";
	case 2737:
		return "SRP Feedback";
	case 2738:
		return "NDL TCP-OSI Gateway";
	case 2739:
		return "TN Timing";
	case 2740:
		return "Alarm";
	case 2741:
		return "TSB";
	case 2742:
		return "TSB2";
	case 2743:
		return "murx";
	case 2744:
		return "honyaku";
	case 2745:
		return "URBISNET";
	case 2746:
		return "CPUDPENCAP";
	case 2747:
		return "";
	case 2748:
		return "";
	case 2749:
		return "";
	case 2750:
		return "";
	case 2751:
		return "";
	case 2752:
		return "RSISYS ACCESS";
	case 2753:
		return "de-spot";
	case 2754:
		return "APOLLO CC";
	case 2755:
		return "Express Pay";
	case 2756:
		return "simplement-tie";
	case 2757:
		return "CNRP";
	case 2758:
		return "APOLLO Status";
	case 2759:
		return "APOLLO GMS";
	case 2760:
		return "Saba MS";
	case 2761:
		return "DICOM ISCL";
	case 2762:
		return "DICOM TLS";
	case 2763:
		return "Desktop DNA";
	case 2764:
		return "Data Insurance";
	case 2765:
		return "qip-audup";
	case 2766:
		return "Compaq SCP";
	case 2767:
		return "UADTC";
	case 2768:
		return "UACS";
	case 2769:
		return "eXcE";
	case 2770:
		return "Veronica";
	case 2771:
		return "Vergence CM";
	case 2772:
		return "auris";
	case 2773:
		return "RBackup Remote Backup";
	case 2774:
		return "RBackup Remote Backup";
	case 2775:
		return "SMPP";
	case 2776:
		return "Ridgeway Systems & Software";
	case 2777:
		return "Ridgeway Systems & Software";
	case 2778:
		return "Gwen-Sonya";
	case 2779:
		return "LBC Sync";
	case 2780:
		return "LBC Control";
	case 2781:
		return "whosells";
	case 2782:
		return "everydayrc";
	case 2783:
		return "AISES";
	case 2784:
		return "world wide web - development";
	case 2785:
		return "aic-np";
	case 2786:
		return "aic-oncrpc - Destiny MCD database";
	case 2787:
		return "piccolo - Cornerstone Software";
	case 2788:
		return "NetWare Loadable Module - Seagate Software";
	case 2789:
		return "Media Agent";
	case 2790:
		return "PLG Proxy";
	case 2791:
		return "MT Port Registrator";
	case 2792:
		return "f5-globalsite";
	case 2793:
		return "initlsmsad";
	case 2795:
		return "LiveStats";
	case 2796:
		return "ac-tech";
	case 2797:
		return "esp-encap";
	case 2798:
		return "TMESIS-UPShot";
	case 2799:
		return "ICON Discover";
	case 2800:
		return "ACC RAID";
	case 2801:
		return "IGCP";
	case 2802:
		return "Veritas TCP1";
	case 2803:
		return "btprjctrl";
	case 2804:
		return "March Networks Digital Video Recorders and Enterprise Service Manager products";
	case 2805:
		return "WTA WSP-S";
	case 2806:
		return "cspuni";
	case 2807:
		return "cspmulti";
	case 2808:
		return "J-LAN-P";
	case 2809:
		return "CORBA LOC";
	case 2810:
		return "Active Net Steward";
	case 2811:
		return "GSI FTP";
	case 2812:
		return "atmtcp";
	case 2813:
		return "llm-pass";
	case 2814:
		return "llm-csv";
	case 2815:
		return "LBC Measurement";
	case 2816:
		return "LBC Watchdog";
	case 2817:
		return "NMSig Port";
	case 2818:
		return "rmlnk";
	case 2819:
		return "FC Fault Notification";
	case 2820:
		return "UniVision";
	case 2821:
		return "VERITAS Authentication Service";
	case 2822:
		return "ka0wuc";
	case 2823:
		return "CQG Net/LAN";
	case 2824:
		return "CQG Net/LAN 1";
	case 2826:
		return "slc systemlog";
	case 2827:
		return "slc ctrlrloops";
	case 2828:
		return "ITM License Manager";
	case 2829:
		return "silkp1";
	case 2830:
		return "silkp2";
	case 2831:
		return "silkp3";
	case 2832:
		return "silkp4";
	case 2833:
		return "glishd";
	case 2834:
		return "EVTP";
	case 2835:
		return "EVTP-DATA";
	case 2836:
		return "catalyst";
	case 2837:
		return "Repliweb";
	case 2838:
		return "Starbot";
	case 2839:
		return "NMSigPort";
	case 2840:
		return "l3-exprt";
	case 2841:
		return "l3-ranger";
	case 2842:
		return "l3-hawk";
	case 2843:
		return "PDnet";
	case 2844:
		return "BPCP POLL";
	case 2845:
		return "BPCP TRAP";
	case 2846:
		return "AIMPP Hello";
	case 2847:
		return "AIMPP Port Req";
	case 2848:
		return "AMT-BLC-PORT";
	case 2849:
		return "FXP";
	case 2850:
		return "MetaConsole";
	case 2851:
		return "webemshttp";
	case 2852:
		return "bears-01";
	case 2853:
		return "ISPipes";
	case 2854:
		return "InfoMover";
	case 2855:
		return "MSRP over TCP";
	case 2856:
		return "cesdinv";
	case 2857:
		return "SimCtIP";
	case 2858:
		return "ECNP";
	case 2859:
		return "Active Memory";
	case 2860:
		return "Dialpad Voice 1";
	case 2861:
		return "Dialpad Voice 2";
	case 2862:
		return "TTG Protocol";
	case 2863:
		return "Sonar Data";
	case 2864:
		return "main 5001 cmd";
	case 2865:
		return "pit-vpn";
	case 2866:
		return "iwlistener";
	case 2867:
		return "esps-portal";
	case 2868:
		return "Norman Proprietaqry Events Protocol";
	case 2869:
		return "ICSLAP";
	case 2870:
		return "daishi";
	case 2871:
		return "MSI Select Play";
	case 2872:
		return "RADIX";
	case 2873:
		return "PubSub Realtime Telemetry Protocol";
	case 2874:
		return "DX Message Base Transport Protocol";
	case 2875:
		return "DX Message Base Transport Protocol";
	case 2876:
		return "SPS Tunnel";
	case 2877:
		return "BLUELANCE";
	case 2878:
		return "AAP";
	case 2879:
		return "ucentric-ds";
	case 2880:
		return "Synapse Transport";
	case 2881:
		return "NDSP";
	case 2882:
		return "NDTP";
	case 2883:
		return "NDNP";
	case 2884:
		return "Flash Msg";
	case 2885:
		return "TopFlow";
	case 2886:
		return "RESPONSELOGIC";
	case 2887:
		return "aironet";
	case 2888:
		return "SPCSDLOBBY";
	case 2889:
		return "RSOM";
	case 2890:
		return "CSPCLMULTI";
	case 2891:
		return "CINEGRFX-ELMD License Manager";
	case 2892:
		return "SNIFFERDATA";
	case 2893:
		return "VSECONNECTOR";
	case 2894:
		return "ABACUS-REMOTE";
	case 2895:
		return "NATUS LINK";
	case 2896:
		return "ECOVISIONG6-1";
	case 2897:
		return "Citrix RTMP";
	case 2898:
		return "APPLIANCE-CFG";
	case 2899:
		return "POWERGEMPLUS";
	case 2900:
		return "QUICKSUITE";
	case 2901:
		return "ALLSTORCNS";
	case 2902:
		return "NET ASPI";
	case 2903:
		return "SUITCASE";
	case 2904:
		return "M2UA";
	case 2905:
		return "M3UA";
	case 2906:
		return "CALLER9";
	case 2907:
		return "WEBMETHODS B2B";
	case 2908:
		return "mao";
	case 2909:
		return "Funk Dialout";
	case 2910:
		return "TDAccess";
	case 2911:
		return "Blockade";
	case 2912:
		return "Epicon";
	case 2913:
		return "Booster Ware";
	case 2914:
		return "Game Lobby";
	case 2915:
		return "TK Socket";
	case 2916:
		return "Elvin Server IANA assigned this well-formed service name as a replacement for elvin_server.";
	case 2917:
		return "Elvin Client IANA assigned this well-formed service name as a replacement for elvin_client.";
	case 2918:
		return "Kasten Chase Pad";
	case 2919:
		return "roboER";
	case 2920:
		return "roboEDA";
	case 2921:
		return "CESD Contents Delivery Management";
	case 2922:
		return "CESD Contents Delivery Data Transfer";
	case 2923:
		return "WTA-WSP-WTP-S";
	case 2924:
		return "PRECISE-VIP";
	case 2926:
		return "MOBILE-FILE-DL";
	case 2927:
		return "UNIMOBILECTRL";
	case 2928:
		return "REDSTONE-CPSS";
	case 2929:
		return "AMX-WEBADMIN";
	case 2930:
		return "AMX-WEBLINX";
	case 2931:
		return "Circle-X";
	case 2932:
		return "INCP";
	case 2933:
		return "4-TIER OPM GW";
	case 2934:
		return "4-TIER OPM CLI";
	case 2935:
		return "QTP";
	case 2936:
		return "OTPatch";
	case 2937:
		return "PNACONSULT-LM";
	case 2938:
		return "SM-PAS-1";
	case 2939:
		return "SM-PAS-2";
	case 2940:
		return "SM-PAS-3";
	case 2941:
		return "SM-PAS-4";
	case 2942:
		return "SM-PAS-5";
	case 2943:
		return "TTNRepository";
	case 2944:
		return "Megaco H-248";
	case 2945:
		return "H248 Binary";
	case 2946:
		return "FJSVmpor";
	case 2947:
		return "GPS Daemon request/response protocol";
	case 2948:
		return "WAP PUSH";
	case 2949:
		return "WAP PUSH SECURE";
	case 2950:
		return "ESIP";
	case 2951:
		return "OTTP";
	case 2952:
		return "MPFWSAS";
	case 2953:
		return "OVALARMSRV";
	case 2954:
		return "OVALARMSRV-CMD";
	case 2955:
		return "CSNOTIFY";
	case 2956:
		return "OVRIMOSDBMAN";
	case 2957:
		return "JAMCT5";
	case 2958:
		return "JAMCT6";
	case 2959:
		return "RMOPAGT";
	case 2960:
		return "DFOXSERVER";
	case 2961:
		return "BOLDSOFT-LM";
	case 2962:
		return "IPH-POLICY-CLI";
	case 2963:
		return "IPH-POLICY-ADM";
	case 2964:
		return "BULLANT SRAP";
	case 2965:
		return "BULLANT RAP";
	case 2966:
		return "IDP-INFOTRIEVE";
	case 2967:
		return "SSC-AGENT";
	case 2968:
		return "ENPP";
	case 2969:
		return "ESSP";
	case 2970:
		return "INDEX-NET";
	case 2971:
		return "NetClip clipboard daemon";
	case 2972:
		return "PMSM Webrctl";
	case 2973:
		return "SV Networks";
	case 2974:
		return "Signal";
	case 2975:
		return "Fujitsu Configuration Management Service";
	case 2976:
		return "CNS Server Port";
	case 2977:
		return "TTCs Enterprise Test Access Protocol - NS";
	case 2978:
		return "TTCs Enterprise Test Access Protocol - DS";
	case 2979:
		return "H.263 Video Streaming";
	case 2980:
		return "Instant Messaging Service";
	case 2981:
		return "MYLXAMPORT";
	case 2982:
		return "IWB-WHITEBOARD";
	case 2983:
		return "NETPLAN";
	case 2984:
		return "HPIDSADMIN";
	case 2985:
		return "HPIDSAGENT";
	case 2986:
		return "STONEFALLS";
	case 2987:
		return "identify";
	case 2988:
		return "HIPPA Reporting Protocol";
	case 2989:
		return "ZARKOV Intelligent Agent Communication";
	case 2990:
		return "BOSCAP";
	case 2991:
		return "WKSTN-MON";
	case 2992:
		return "Avenyo Server";
	case 2993:
		return "VERITAS VIS1";
	case 2994:
		return "VERITAS VIS2";
	case 2995:
		return "IDRS";
	case 2996:
		return "vsixml";
	case 2997:
		return "REBOL";
	case 2998:
		return "Real Secure";
	case 2999:
		return "RemoteWare Unassigned";
	case 3000:
		return "HBCI";
	case 3001:
		return "OrigoDB Server Native Interface";
	case 3002:
		return "EXLM Agent";
	case 3003:
		return "CGMS";
	case 3004:
		return "Csoft Agent";
	case 3005:
		return "Genius License Manager";
	case 3006:
		return "Instant Internet Admin";
	case 3007:
		return "Lotus Mail Tracking Agent Protocol";
	case 3008:
		return "Midnight Technologies";
	case 3009:
		return "PXC-NTFY";
	case 3010:
		return "Telerate Workstation";
	case 3011:
		return "Trusted Web";
	case 3012:
		return "Trusted Web Client";
	case 3013:
		return "Gilat Sky Surfer";
	case 3014:
		return "Broker Service IANA assigned this well-formed service name as a replacement for broker_service.";
	case 3015:
		return "NATI DSTP";
	case 3016:
		return "Notify Server IANA assigned this well-formed service name as a replacement for notify_srvr.";
	case 3017:
		return "Event Listener IANA assigned this well-formed service name as a replacement for event_listener.";
	case 3018:
		return "Service Registry IANA assigned this well-formed service name as a replacement for srvc_registry.";
	case 3019:
		return "Resource Manager IANA assigned this well-formed service name as a replacement for resource_mgr.";
	case 3020:
		return "CIFS";
	case 3021:
		return "AGRI Server";
	case 3022:
		return "CSREGAGENT";
	case 3023:
		return "magicnotes";
	case 3024:
		return "NDS_SSO IANA assigned this well-formed service name as a replacement for nds_sso.";
	case 3025:
		return "Arepa Raft";
	case 3026:
		return "AGRI Gateway";
	case 3027:
		return "LiebDevMgmt_C IANA assigned this well-formed service name as a replacement for LiebDevMgmt_C.";
	case 3028:
		return "LiebDevMgmt_DM IANA assigned this well-formed service name as a replacement for LiebDevMgmt_DM.";
	case 3029:
		return "LiebDevMgmt_A IANA assigned this well-formed service name as a replacement for LiebDevMgmt_A.";
	case 3030:
		return "Arepa Cas";
	case 3031:
		return "Remote AppleEvents/PPC Toolbox";
	case 3032:
		return "Redwood Chat";
	case 3033:
		return "PDB";
	case 3034:
		return "Osmosis / Helix (R) AEEA Port";
	case 3035:
		return "FJSV gssagt";
	case 3036:
		return "Hagel DUMP";
	case 3037:
		return "HP SAN Mgmt";
	case 3038:
		return "Santak UPS";
	case 3039:
		return "Cogitate";
	case 3040:
		return "Tomato Springs";
	case 3041:
		return "di-traceware";
	case 3042:
		return "journee";
	case 3043:
		return "Broadcast Routing Protocol";
	case 3044:
		return "EndPoint Protocol";
	case 3045:
		return "ResponseNet";
	case 3046:
		return "di-ase";
	case 3047:
		return "Fast Security HL Server";
	case 3048:
		return "Sierra Net PC Trader";
	case 3049:
		return "NSWS";
	case 3050:
		return "gds_db IANA assigned this well-formed service name as a replacement for gds_db.";
	case 3051:
		return "Galaxy Server";
	case 3052:
		return "APC 3052";
	case 3053:
		return "dsom-server";
	case 3054:
		return "AMT CNF PROT";
	case 3055:
		return "Policy Server";
	case 3056:
		return "CDL Server";
	case 3057:
		return "GoAhead FldUp";
	case 3058:
		return "videobeans";
	case 3059:
		return "qsoft";
	case 3060:
		return "interserver";
	case 3061:
		return "cautcpd";
	case 3062:
		return "ncacn-ip-tcp";
	case 3063:
		return "ncadg-ip-udp";
	case 3064:
		return "Remote Port Redirector";
	case 3065:
		return "slinterbase";
	case 3066:
		return "NETATTACHSDMP";
	case 3067:
		return "FJHPJP";
	case 3068:
		return "ls3 Broadcast";
	case 3069:
		return "ls3";
	case 3070:
		return "MGXSWITCH";
	case 3071:
		return "Crossplatform replication protocol";
	case 3072:
		return "ContinuStor Monitor Port";
	case 3073:
		return "Very simple chatroom prot";
	case 3074:
		return "Xbox game port";
	case 3075:
		return "Orbix 2000 Locator";
	case 3076:
		return "Orbix 2000 Config";
	case 3077:
		return "Orbix 2000 Locator SSL";
	case 3078:
		return "Orbix 2000 Locator SSL";
	case 3079:
		return "LV Front Panel";
	case 3080:
		return "stm_pproc IANA assigned this well-formed service name as a replacement for stm_pproc.";
	case 3081:
		return "TL1-LV";
	case 3082:
		return "TL1-RAW";
	case 3083:
		return "TL1-TELNET";
	case 3084:
		return "ITM-MCCS";
	case 3085:
		return "PCIHReq";
	case 3086:
		return "JDL-DBKitchen";
	case 3087:
		return "Asoki SMA";
	case 3088:
		return "eXtensible Data Transfer Protocol";
	case 3089:
		return "ParaTek Agent Linking";
	case 3090:
		return "Senforce Session Services";
	case 3091:
		return "1Ci Server Management";
	case 3093:
		return "Jiiva RapidMQ Center";
	case 3094:
		return "Jiiva RapidMQ Registry";
	case 3095:
		return "Panasas rendezvous port";
	case 3096:
		return "Active Print Server Port";
	case 3097:
		return "Reserved";
	case 3098:
		return "Universal Message Manager";
	case 3099:
		return "CHIPSY Machine Daemon";
	case 3100:
		return "OpCon/xps";
	case 3101:
		return "HP PolicyXpert PIB Server";
	case 3102:
		return "SoftlinK Slave Mon Port";
	case 3103:
		return "Autocue SMI Protocol";
	case 3104:
		return "Autocue Logger Protocol";
	case 3105:
		return "Cardbox";
	case 3106:
		return "Cardbox HTTP";
	case 3107:
		return "Business protocol";
	case 3108:
		return "Geolocate protocol";
	case 3109:
		return "Personnel protocol";
	case 3110:
		return "simulator control port";
	case 3111:
		return "Web Synchronous Services";
	case 3112:
		return "KDE System Guard";
	case 3113:
		return "CS-Authenticate Svr Port";
	case 3114:
		return "CCM AutoDiscover";
	case 3115:
		return "MCTET Master";
	case 3116:
		return "MCTET Gateway";
	case 3117:
		return "MCTET Jserv";
	case 3118:
		return "PKAgent";
	case 3119:
		return "D2000 Kernel Port";
	case 3120:
		return "D2000 Webserver Port";
	case 3121:
		return "The pacemaker remote (pcmk-remote) service extends high availability functionality outside of the Linux cluster into remote nodes.";
	case 3122:
		return "MTI VTR Emulator port";
	case 3123:
		return "EDI Translation Protocol";
	case 3124:
		return "Beacon Port";
	case 3125:
		return "A13-AN Interface";
	case 3127:
		return "CTX Bridge Port";
	case 3128:
		return "Active API Server Port";
	case 3129:
		return "NetPort Discovery Port";
	case 3130:
		return "ICPv2";
	case 3131:
		return "Net Book Mark";
	case 3132:
		return "Microsoft Business Rule Engine Update Service";
	case 3133:
		return "Prism Deploy User Port";
	case 3134:
		return "Extensible Code Protocol";
	case 3135:
		return "PeerBook Port";
	case 3136:
		return "Grub Server Port";
	case 3137:
		return "rtnt-1 data packets";
	case 3138:
		return "rtnt-2 data packets";
	case 3139:
		return "Incognito Rendez-Vous";
	case 3140:
		return "Arilia Multiplexor";
	case 3141:
		return "VMODEM";
	case 3142:
		return "RDC WH EOS";
	case 3143:
		return "Sea View";
	case 3144:
		return "Tarantella";
	case 3145:
		return "CSI-LFAP";
	case 3146:
		return "bears-02";
	case 3147:
		return "RFIO";
	case 3148:
		return "NetMike Game Administrator";
	case 3149:
		return "NetMike Game Server";
	case 3150:
		return "NetMike Assessor Administrator";
	case 3151:
		return "NetMike Assessor";
	case 3152:
		return "FeiTian Port";
	case 3153:
		return "S8Cargo Client Port";
	case 3154:
		return "ON RMI Registry";
	case 3155:
		return "JpegMpeg Port";
	case 3156:
		return "Indura Collector";
	case 3157:
		return "CCC Listener Port";
	case 3158:
		return "SmashTV Protocol";
	case 3159:
		return "NavegaWeb Tarification";
	case 3160:
		return "TIP Application Server";
	case 3161:
		return "DOC1 License Manager";
	case 3162:
		return "SFLM";
	case 3163:
		return "RES-SAP";
	case 3164:
		return "IMPRS";
	case 3165:
		return "Newgenpay Engine Service";
	case 3166:
		return "Quest Spotlight Out-Of-Process Collector";
	case 3167:
		return "Now Contact Public Server";
	case 3168:
		return "Now Up-to-Date Public Server";
	case 3169:
		return "SERVERVIEW-AS";
	case 3170:
		return "SERVERVIEW-ASN";
	case 3171:
		return "SERVERVIEW-GF";
	case 3172:
		return "SERVERVIEW-RM";
	case 3173:
		return "SERVERVIEW-ICC";
	case 3174:
		return "ARMI Server";
	case 3175:
		return "T1_E1_Over_IP";
	case 3176:
		return "ARS Master";
	case 3177:
		return "Phonex Protocol";
	case 3178:
		return "Radiance UltraEdge Port";
	case 3179:
		return "H2GF W.2m Handover prot.";
	case 3180:
		return "Millicent Broker Server";
	case 3181:
		return "BMC Patrol Agent";
	case 3182:
		return "BMC Patrol Rendezvous";
	case 3183:
		return "COPS/TLS";
	case 3184:
		return "ApogeeX Port";
	case 3185:
		return "SuSE Meta PPPD";
	case 3186:
		return "IIW Monitor User Port";
	case 3187:
		return "Open Design Listen Port";
	case 3188:
		return "Broadcom Port";
	case 3189:
		return "Pinnacle Sys InfEx Port";
	case 3190:
		return "ConServR Proxy";
	case 3191:
		return "ConServR SSL Proxy";
	case 3192:
		return "FireMon Revision Control";
	case 3193:
		return "SpanDataPort";
	case 3194:
		return "Rockstorm MAG protocol";
	case 3195:
		return "Network Control Unit";
	case 3196:
		return "Network Control Unit";
	case 3197:
		return "Embrace Device Protocol Server";
	case 3198:
		return "Embrace Device Protocol Client";
	case 3199:
		return "DMOD WorkSpace";
	case 3200:
		return "Press-sense Tick Port";
	case 3201:
		return "CPQ-TaskSmart";
	case 3202:
		return "IntraIntra";
	case 3203:
		return "Network Watcher Monitor";
	case 3204:
		return "Network Watcher DB Access";
	case 3205:
		return "iSNS Server Port";
	case 3206:
		return "IronMail POP Proxy";
	case 3207:
		return "Veritas Authentication Port";
	case 3208:
		return "PFU PR Callback";
	case 3209:
		return "HP OpenView Network Path Engine Server";
	case 3210:
		return "Flamenco Networks Proxy";
	case 3211:
		return "Avocent Secure Management";
	case 3212:
		return "Survey Instrument";
	case 3213:
		return "NEON 24X7 Mission Control";
	case 3214:
		return "JMQ Daemon Port 1";
	case 3215:
		return "JMQ Daemon Port 2";
	case 3216:
		return "Ferrari electronic FOAM";
	case 3217:
		return "Unified IP & Telecom Environment";
	case 3218:
		return "EMC SmartPackets";
	case 3219:
		return "WMS Messenger";
	case 3220:
		return "XML NM over SSL";
	case 3221:
		return "XML NM over TCP";
	case 3222:
		return "Gateway Load Balancing Pr";
	case 3223:
		return "DIGIVOTE (R) Vote-Server";
	case 3224:
		return "AES Discovery Port";
	case 3225:
		return "FCIP";
	case 3226:
		return "ISI Industry Software IRP";
	case 3227:
		return "DiamondWave NMS Server";
	case 3228:
		return "DiamondWave MSG Server";
	case 3229:
		return "Global CD Port";
	case 3230:
		return "Software Distributor Port";
	case 3231:
		return "VidiGo communication (previous was: Delta Solutions Direct)";
	case 3232:
		return "MDT port";
	case 3233:
		return "WhiskerControl main port";
	case 3234:
		return "Alchemy Server";
	case 3235:
		return "MDAP port";
	case 3236:
		return "appareNet Test Server";
	case 3237:
		return "appareNet Test Packet Sequencer";
	case 3238:
		return "appareNet Analysis Server";
	case 3239:
		return "appareNet User Interface";
	case 3240:
		return "Trio Motion Control Port";
	case 3241:
		return "SysOrb Monitoring Server";
	case 3242:
		return "Session Description ID";
	case 3243:
		return "Timelot Port";
	case 3244:
		return "OneSAF";
	case 3245:
		return "VIEO Fabric Executive";
	case 3246:
		return "DVT SYSTEM PORT";
	case 3247:
		return "DVT DATA LINK";
	case 3248:
		return "PROCOS LM";
	case 3249:
		return "State Sync Protocol";
	case 3250:
		return "HMS hicp port";
	case 3251:
		return "Sys Scanner";
	case 3252:
		return "DHE port";
	case 3253:
		return "PDA Data";
	case 3254:
		return "PDA System";
	case 3255:
		return "Semaphore Connection Port";
	case 3256:
		return "Compaq RPM Agent Port";
	case 3257:
		return "Compaq RPM Server Port";
	case 3258:
		return "Ivecon Server Port";
	case 3259:
		return "Epson Network Common Devi";
	case 3260:
		return "iSCSI port";
	case 3261:
		return "winShadow";
	case 3262:
		return "NECP";
	case 3263:
		return "E-Color Enterprise Imager";
	case 3264:
		return "cc:mail/lotus";
	case 3265:
		return "Altav Tunnel";
	case 3266:
		return "NS CFG Server";
	case 3267:
		return "IBM Dial Out";
	case 3268:
		return "Microsoft Global Catalog";
	case 3269:
		return "Microsoft Global Catalog with LDAP/SSL";
	case 3270:
		return "Verismart";
	case 3271:
		return "CSoft Prev Port";
	case 3272:
		return "Fujitsu User Manager";
	case 3273:
		return "Simple Extensible Multiplexed Protocol";
	case 3274:
		return "Ordinox Server";
	case 3275:
		return "SAMD";
	case 3276:
		return "Maxim ASICs";
	case 3277:
		return "AWG Proxy";
	case 3278:
		return "LKCM Server";
	case 3279:
		return "admind";
	case 3280:
		return "VS Server";
	case 3281:
		return "SYSOPT";
	case 3282:
		return "Datusorb";
	case 3283:
		return "Net Assistant";
	case 3284:
		return "4Talk";
	case 3285:
		return "Plato";
	case 3286:
		return "E-Net";
	case 3287:
		return "DIRECTVDATA";
	case 3288:
		return "COPS";
	case 3289:
		return "ENPC";
	case 3290:
		return "CAPS LOGISTICS TOOLKIT - LM";
	case 3291:
		return "S A Holditch & Associates - LM";
	case 3292:
		return "Cart O Rama";
	case 3293:
		return "fg-fps";
	case 3294:
		return "fg-gip";
	case 3295:
		return "Dynamic IP Lookup";
	case 3296:
		return "Rib License Manager";
	case 3297:
		return "Cytel License Manager";
	case 3298:
		return "DeskView";
	case 3299:
		return "pdrncs";
	case 3300:
		return "Ceph monitor";
	case 3301:
		return "Tarantool in-memory computing platform";
	case 3302:
		return "MCS Fastmail";
	case 3303:
		return "OP Session Client";
	case 3304:
		return "OP Session Server";
	case 3305:
		return "ODETTE-FTP";
	case 3306:
		return "MySQL";
	case 3307:
		return "OP Session Proxy";
	case 3308:
		return "TNS Server";
	case 3309:
		return "TNS ADV";
	case 3310:
		return "Dyna Access";
	case 3311:
		return "MCNS Tel Ret";
	case 3312:
		return "Application Management Server";
	case 3313:
		return "Unify Object Broker";
	case 3314:
		return "Unify Object Host";
	case 3315:
		return "CDID";
	case 3316:
		return "AICC/CMI";
	case 3317:
		return "VSAI PORT";
	case 3318:
		return "Swith to Swith Routing Information Protocol";
	case 3319:
		return "SDT License Manager";
	case 3320:
		return "Office Link 2000";
	case 3321:
		return "VNSSTR";
	case 3326:
		return "SFTU";
	case 3327:
		return "BBARS";
	case 3328:
		return "Eaglepoint License Manager";
	case 3329:
		return "HP Device Disc";
	case 3330:
		return "MCS Calypso ICF";
	case 3331:
		return "MCS Messaging";
	case 3332:
		return "MCS Mail Server";
	case 3333:
		return "DEC Notes";
	case 3334:
		return "Direct TV Webcasting";
	case 3335:
		return "Direct TV Software Updates";
	case 3336:
		return "Direct TV Tickers";
	case 3337:
		return "Direct TV Data Catalog";
	case 3338:
		return "OMF data b";
	case 3339:
		return "OMF data l";
	case 3340:
		return "OMF data m";
	case 3341:
		return "OMF data h";
	case 3342:
		return "WebTIE";
	case 3343:
		return "MS Cluster Net";
	case 3344:
		return "BNT Manager";
	case 3345:
		return "Influence";
	case 3346:
		return "Trnsprnt Proxy";
	case 3347:
		return "Phoenix RPC";
	case 3348:
		return "Pangolin Laser";
	case 3349:
		return "Chevin Services";
	case 3350:
		return "FINDVIATV";
	case 3351:
		return "Btrieve port";
	case 3352:
		return "Scalable SQL";
	case 3353:
		return "FATPIPE";
	case 3354:
		return "SUITJD";
	case 3355:
		return "Ordinox Dbase";
	case 3356:
		return "UPNOTIFYPS";
	case 3357:
		return "Adtech Test IP";
	case 3358:
		return "Mp Sys Rmsvr";
	case 3359:
		return "WG NetForce";
	case 3360:
		return "KV Server";
	case 3361:
		return "KV Agent";
	case 3362:
		return "DJ ILM";
	case 3363:
		return "NATI Vi Server";
	case 3364:
		return "Creative Server";
	case 3365:
		return "Content Server";
	case 3366:
		return "Creative Partner";
	case 3372:
		return "TIP 2";
	case 3373:
		return "Lavenir License Manager";
	case 3374:
		return "Cluster Disc";
	case 3375:
		return "VSNM Agent";
	case 3376:
		return "CD Broker";
	case 3377:
		return "Cogsys Network License Manager";
	case 3378:
		return "WSICOPY";
	case 3379:
		return "SOCORFS";
	case 3380:
		return "SNS Channels";
	case 3381:
		return "Geneous";
	case 3382:
		return "Fujitsu Network Enhanced Antitheft function";
	case 3383:
		return "Enterprise Software Products License Manager";
	case 3384:
		return "Cluster Management Services";
	case 3385:
		return "qnxnetman";
	case 3386:
		return "GPRS Data";
	case 3387:
		return "Back Room Net";
	case 3388:
		return "CB Server";
	case 3389:
		return "MS WBT Server";
	case 3390:
		return "Distributed Service Coordinator";
	case 3391:
		return "SAVANT";
	case 3392:
		return "EFI License Management";
	case 3393:
		return "D2K Tapestry Client to Server";
	case 3394:
		return "D2K Tapestry Server to Server";
	case 3395:
		return "Dyna License Manager (Elam)";
	case 3396:
		return "Printer Agent IANA assigned this well-formed service name as a replacement for printer_agent.";
	case 3397:
		return "Cloanto License Manager";
	case 3398:
		return "Mercantile";
	case 3399:
		return "CSMS";
	case 3400:
		return "CSMS2";
	case 3401:
		return "filecast";
	case 3402:
		return "FXa Engine Network Port";
	case 3405:
		return "Nokia Announcement ch 1";
	case 3406:
		return "Nokia Announcement ch 2";
	case 3407:
		return "LDAP admin server port";
	case 3408:
		return "BES Api Port";
	case 3409:
		return "NetworkLens Event Port";
	case 3410:
		return "NetworkLens SSL Event";
	case 3411:
		return "BioLink Authenteon server";
	case 3412:
		return "xmlBlaster";
	case 3413:
		return "SpecView Networking";
	case 3414:
		return "BroadCloud WIP Port";
	case 3415:
		return "BCI Name Service";
	case 3416:
		return "AirMobile IS Command Port";
	case 3417:
		return "ConServR file translation";
	case 3418:
		return "Remote nmap";
	case 3419:
		return "Isogon SoftAudit";
	case 3420:
		return "iFCP User Port";
	case 3421:
		return "Bull Apprise portmapper";
	case 3422:
		return "Remote USB System Port";
	case 3423:
		return "xTrade Reliable Messaging";
	case 3424:
		return "xTrade over TLS/SSL";
	case 3425:
		return "AGPS Access Port";
	case 3426:
		return "Arkivio Storage Protocol";
	case 3427:
		return "WebSphere SNMP";
	case 3428:
		return "2Wire CSS";
	case 3429:
		return "GCSP user port";
	case 3430:
		return "Scott Studios Dispatch";
	case 3431:
		return "Active License Server Port";
	case 3432:
		return "Secure Device Protocol";
	case 3433:
		return "OPNET Service Management Platform";
	case 3434:
		return "OpenCM Server";
	case 3435:
		return "Pacom Security User Port";
	case 3436:
		return "GuardControl Exchange Protocol";
	case 3437:
		return "Autocue Directory Service";
	case 3438:
		return "Spiralcraft Admin";
	case 3439:
		return "HRI Interface Port";
	case 3440:
		return "Net Steward Mgmt Console";
	case 3441:
		return "OC Connect Client";
	case 3442:
		return "OC Connect Server";
	case 3443:
		return "OpenView Network Node Manager WEB Server";
	case 3444:
		return "Denali Server";
	case 3445:
		return "Media Object Network Protocol";
	case 3446:
		return "3Com FAX RPC port";
	case 3447:
		return "DirectNet IM System";
	case 3448:
		return "Discovery and Net Config";
	case 3449:
		return "HotU Chat";
	case 3450:
		return "CAStorProxy";
	case 3451:
		return "ASAM Services";
	case 3452:
		return "SABP-Signalling Protocol";
	case 3453:
		return "PSC Update";
	case 3454:
		return "Apple Remote Access Protocol";
	case 3455:
		return "RSVP Port";
	case 3456:
		return "VAT default data";
	case 3457:
		return "VAT default control";
	case 3458:
		return "D3WinOSFI";
	case 3459:
		return "TIP Integral";
	case 3460:
		return "EDM Manger";
	case 3461:
		return "EDM Stager";
	case 3462:
		return "EDM STD Notify";
	case 3463:
		return "EDM ADM Notify";
	case 3464:
		return "EDM MGR Sync";
	case 3465:
		return "EDM MGR Cntrl";
	case 3466:
		return "WORKFLOW";
	case 3467:
		return "RCST";
	case 3468:
		return "TTCM Remote Controll";
	case 3469:
		return "Pluribus";
	case 3470:
		return "jt400";
	case 3471:
		return "jt400-ssl";
	case 3472:
		return "JAUGS N-G Remotec 1";
	case 3473:
		return "JAUGS N-G Remotec 2";
	case 3474:
		return "TSP Automation";
	case 3475:
		return "Genisar Comm Port";
	case 3476:
		return "NVIDIA Mgmt Protocol";
	case 3477:
		return "eComm link port";
	case 3478:
		return "Session Traversal Utilities for NAT (STUN) port";
	case 3479:
		return "2Wire RPC";
	case 3480:
		return "Secure Virtual Workspace";
	case 3481:
		return "CleanerLive remote ctrl";
	case 3482:
		return "Vulture Monitoring System";
	case 3483:
		return "Slim Devices Protocol";
	case 3484:
		return "GBS SnapTalk Protocol";
	case 3485:
		return "CelaTalk";
	case 3486:
		return "IFSF Heartbeat Port";
	case 3487:
		return "LISA TCP Transfer Channel";
	case 3488:
		return "FS Remote Host Server";
	case 3489:
		return "DTP/DIA";
	case 3490:
		return "Colubris Management Port";
	case 3491:
		return "SWR Port";
	case 3492:
		return "TVDUM Tray Port";
	case 3493:
		return "Network UPS Tools";
	case 3494:
		return "IBM 3494";
	case 3495:
		return "securitylayer over tcp";
	case 3496:
		return "securitylayer over tls";
	case 3497:
		return "ipEther232Port";
	case 3498:
		return "DASHPAS user port";
	case 3499:
		return "SccIP Media";
	case 3500:
		return "RTMP Port";
	case 3501:
		return "iSoft-P2P";
	case 3502:
		return "Avocent Install Discovery";
	case 3503:
		return "MPLS LSP-echo Port";
	case 3504:
		return "IronStorm game server";
	case 3505:
		return "CCM communications port";
	case 3506:
		return "APC 3506";
	case 3507:
		return "Nesh Broker Port";
	case 3508:
		return "Interaction Web";
	case 3509:
		return "Virtual Token SSL Port";
	case 3510:
		return "XSS Port";
	case 3511:
		return "WebMail/2";
	case 3512:
		return "Aztec Distribution Port";
	case 3513:
		return "Adaptec Remote Protocol";
	case 3514:
		return "MUST Peer to Peer";
	case 3515:
		return "MUST Backplane";
	case 3516:
		return "Smartcard Port";
	case 3517:
		return "IEEE 802.11 WLANs WG IAPP";
	case 3518:
		return "Artifact Message Server";
	case 3519:
		return "Netvion Messenger Port";
	case 3520:
		return "Netvion Galileo Log Port";
	case 3521:
		return "Telequip Labs MC3SS";
	case 3522:
		return "DO over NSSocketPort";
	case 3523:
		return "Odeum Serverlink";
	case 3524:
		return "ECM Server port";
	case 3525:
		return "EIS Server port";
	case 3526:
		return "starQuiz Port";
	case 3527:
		return "VERITAS Backup Exec Server";
	case 3528:
		return "JBoss IIOP";
	case 3529:
		return "JBoss IIOP/SSL";
	case 3530:
		return "Grid Friendly";
	case 3531:
		return "Joltid";
	case 3532:
		return "Raven Remote Management Control";
	case 3533:
		return "Raven Remote Management Data";
	case 3534:
		return "URL Daemon Port";
	case 3535:
		return "MS-LA";
	case 3536:
		return "SNAC";
	case 3537:
		return "Remote NI-VISA port";
	case 3538:
		return "IBM Directory Server";
	case 3539:
		return "IBM Directory Server SSL";
	case 3540:
		return "PNRP User Port";
	case 3541:
		return "VoiSpeed Port";
	case 3542:
		return "HA cluster monitor";
	case 3543:
		return "qftest Lookup Port";
	case 3544:
		return "Teredo Port";
	case 3545:
		return "CAMAC equipment";
	case 3547:
		return "Symantec SIM";
	case 3548:
		return "Interworld";
	case 3549:
		return "Tellumat MDR NMS";
	case 3550:
		return "Secure SMPP";
	case 3551:
		return "Apcupsd Information Port";
	case 3552:
		return "TeamAgenda Server Port";
	case 3553:
		return "Red Box Recorder ADP";
	case 3554:
		return "Quest Notification Server";
	case 3555:
		return "Vipul's Razor";
	case 3556:
		return "Sky Transport Protocol";
	case 3557:
		return "PersonalOS Comm Port";
	case 3558:
		return "MCP user port";
	case 3559:
		return "CCTV control port";
	case 3560:
		return "INIServe port";
	case 3561:
		return "BMC-OneKey";
	case 3562:
		return "SDBProxy";
	case 3563:
		return "Watcom Debug";
	case 3564:
		return "Electromed SIM port";
	case 3565:
		return "M2PA";
	case 3566:
		return "Quest Data Hub";
	case 3567:
		return "DOF Protocol Stack";
	case 3568:
		return "DOF Secure Tunnel";
	case 3569:
		return "Meinberg Control Service";
	case 3570:
		return "MCC Web Server Port";
	case 3571:
		return "MegaRAID Server Port";
	case 3572:
		return "Registration Server Port";
	case 3573:
		return "Advantage Group UPS Suite";
	case 3574:
		return "DMAF Server";
	case 3575:
		return "Coalsere CCM Port";
	case 3576:
		return "Coalsere CMC Port";
	case 3577:
		return "Configuration Port";
	case 3578:
		return "Data Port";
	case 3579:
		return "Tarantella Load Balancing";
	case 3580:
		return "NATI-ServiceLocator";
	case 3581:
		return "Ascent Capture Licensing";
	case 3582:
		return "PEG PRESS Server";
	case 3583:
		return "CANEX Watch System";
	case 3584:
		return "U-DBase Access Protocol";
	case 3585:
		return "Emprise License Server";
	case 3586:
		return "License Server Console";
	case 3587:
		return "Peer to Peer Grouping";
	case 3588:
		return "Sentinel Server";
	case 3589:
		return "isomair";
	case 3590:
		return "WV CSP SMS Binding";
	case 3591:
		return "LOCANIS G-TRACK Server";
	case 3592:
		return "LOCANIS G-TRACK NE Port";
	case 3593:
		return "BP Model Debugger";
	case 3594:
		return "MediaSpace";
	case 3595:
		return "ShareApp";
	case 3596:
		return "Illusion Wireless MMOG";
	case 3597:
		return "A14 (AN-to-SC/MM)";
	case 3598:
		return "A15 (AN-to-AN)";
	case 3599:
		return "Quasar Accounting Server";
	case 3600:
		return "text relay-answer";
	case 3601:
		return "Visinet Gui";
	case 3602:
		return "InfiniSwitch Mgr Client";
	case 3603:
		return "Integrated Rcvr Control";
	case 3604:
		return "BMC JMX Port";
	case 3605:
		return "ComCam IO Port";
	case 3606:
		return "Splitlock Server";
	case 3607:
		return "Precise I3";
	case 3608:
		return "Trendchip control protocol";
	case 3609:
		return "CPDI PIDAS Connection Mon";
	case 3610:
		return "ECHONET";
	case 3611:
		return "Six Degrees Port";
	case 3612:
		return "Micro Focus Data Protector";
	case 3613:
		return "Alaris Device Discovery";
	case 3614:
		return "Satchwell Sigma";
	case 3615:
		return "Start Messaging Network";
	case 3616:
		return "cd3o Control Protocol";
	case 3617:
		return "ATI SHARP Logic Engine";
	case 3618:
		return "AAIR-Network 1";
	case 3619:
		return "AAIR-Network 2";
	case 3620:
		return "EPSON Projector Control Port";
	case 3621:
		return "EPSON Network Screen Port";
	case 3622:
		return "FF LAN Redundancy Port";
	case 3623:
		return "HAIPIS Dynamic Discovery";
	case 3624:
		return "Distributed Upgrade Port";
	case 3625:
		return "Volley";
	case 3626:
		return "bvControl Daemon";
	case 3627:
		return "Jam Server Port";
	case 3628:
		return "EPT Machine Interface";
	case 3629:
		return "ESC/VP.net";
	case 3630:
		return "C&S Remote Database Port";
	case 3631:
		return "C&S Web Services Port";
	case 3632:
		return "distributed compiler";
	case 3633:
		return "Wyrnix AIS port";
	case 3634:
		return "hNTSP Library Manager";
	case 3635:
		return "Simple Distributed Objects";
	case 3636:
		return "SerVistaITSM";
	case 3637:
		return "Customer Service Port";
	case 3638:
		return "EHP Backup Protocol";
	case 3639:
		return "Extensible Automation";
	case 3640:
		return "Netplay Port 1";
	case 3641:
		return "Netplay Port 2";
	case 3642:
		return "Juxml Replication port";
	case 3643:
		return "AudioJuggler";
	case 3644:
		return "ssowatch";
	case 3645:
		return "Cyc";
	case 3646:
		return "XSS Server Port";
	case 3647:
		return "Splitlock Gateway";
	case 3648:
		return "Fujitsu Cooperation Port";
	case 3649:
		return "Nishioka Miyuki Msg Protocol";
	case 3650:
		return "PRISMIQ VOD plug-in";
	case 3651:
		return "XRPC Registry";
	case 3652:
		return "VxCR NBU Default Port";
	case 3653:
		return "Tunnel Setup Protocol";
	case 3654:
		return "VAP RealTime Messenger";
	case 3655:
		return "ActiveBatch Exec Agent";
	case 3656:
		return "ActiveBatch Job Scheduler";
	case 3657:
		return "ImmediaNet Beacon";
	case 3658:
		return "PlayStation AMS (Secure)";
	case 3659:
		return "Apple SASL";
	case 3660:
		return "IBM Tivoli Directory Service using SSL";
	case 3661:
		return "IBM Tivoli Directory Service using SSL";
	case 3662:
		return "pserver";
	case 3663:
		return "DIRECWAY Tunnel Protocol";
	case 3664:
		return "UPS Engine Port";
	case 3665:
		return "Enterprise Engine Port";
	case 3666:
		return "IBM eServer PAP";
	case 3667:
		return "IBM Information Exchange";
	case 3668:
		return "Dell Remote Management";
	case 3669:
		return "CA SAN Switch Management";
	case 3670:
		return "SMILE TCP/UDP Interface";
	case 3671:
		return "e Field Control (EIBnet)";
	case 3672:
		return "LispWorks ORB";
	case 3673:
		return "Openview Media Vault GUI";
	case 3674:
		return "WinINSTALL IPC Port";
	case 3675:
		return "CallTrax Data Port";
	case 3676:
		return "VisualAge Pacbase server";
	case 3677:
		return "RoverLog IPC";
	case 3678:
		return "DataGuardianLT";
	case 3679:
		return "Newton Dock";
	case 3680:
		return "NPDS Tracker";
	case 3681:
		return "BTS X73 Port";
	case 3682:
		return "EMC SmartPackets-MAPI";
	case 3683:
		return "BMC EDV/EA";
	case 3684:
		return "FAXstfX";
	case 3685:
		return "DS Expert Agent";
	case 3686:
		return "Trivial Network Management";
	case 3687:
		return "simple-push";
	case 3688:
		return "simple-push Secure";
	case 3689:
		return "Digital Audio Access Protocol (iTunes)";
	case 3690:
		return "Subversion";
	case 3691:
		return "Magaya Network Port";
	case 3692:
		return "Brimstone IntelSync";
	case 3693:
		return "Emergency Automatic Structure Lockdown System";
	case 3695:
		return "BMC Data Collection";
	case 3696:
		return "Telnet Com Port Control";
	case 3697:
		return "NavisWorks License System";
	case 3698:
		return "SAGECTLPANEL";
	case 3699:
		return "Internet Call Waiting";
	case 3700:
		return "LRS NetPage";
	case 3701:
		return "NetCelera";
	case 3702:
		return "Web Service Discovery";
	case 3703:
		return "Adobe Server 3";
	case 3704:
		return "Adobe Server 4";
	case 3705:
		return "Adobe Server 5";
	case 3706:
		return "Real-Time Event Port";
	case 3707:
		return "Real-Time Event Secure Port";
	case 3708:
		return "Sun App Svr - Naming";
	case 3709:
		return "CA-IDMS Server";
	case 3710:
		return "PortGate Authentication";
	case 3711:
		return "EBD Server 2";
	case 3712:
		return "Sentinel Enterprise";
	case 3713:
		return "TFTP over TLS";
	case 3714:
		return "DELOS Direct Messaging";
	case 3715:
		return "Anoto Rendezvous Port";
	case 3716:
		return "WV CSP SMS CIR Channel";
	case 3717:
		return "WV CSP UDP/IP CIR Channel";
	case 3718:
		return "OPUS Server Port";
	case 3719:
		return "iTel Server Port";
	case 3720:
		return "UF Astro. Instr. Services";
	case 3721:
		return "Xsync";
	case 3722:
		return "Xserve RAID";
	case 3723:
		return "Sychron Service Daemon";
	case 3724:
		return "World of Warcraft";
	case 3725:
		return "Netia NA-ER Port";
	case 3726:
		return "Xyratex Array Manager";
	case 3727:
		return "Ericsson Mobile Data Unit";
	case 3728:
		return "Ericsson Web on Air";
	case 3729:
		return "Fireking Audit Port";
	case 3730:
		return "Client Control";
	case 3731:
		return "Service Manager";
	case 3732:
		return "Mobile Wnn";
	case 3733:
		return "Multipuesto Msg Port";
	case 3734:
		return "Synel Data Collection Port";
	case 3735:
		return "Password Distribution";
	case 3736:
		return "RealSpace RMI";
	case 3737:
		return "XPanel Daemon";
	case 3738:
		return "versaTalk Server Port";
	case 3739:
		return "Launchbird LicenseManager";
	case 3740:
		return "Heartbeat Protocol";
	case 3741:
		return "WysDM Agent";
	case 3742:
		return "CST - Configuration & Service Tracker";
	case 3743:
		return "IP Control Systems Ltd.";
	case 3744:
		return "SASG";
	case 3745:
		return "GWRTC Call Port";
	case 3746:
		return "LXPRO.COM LinkTest";
	case 3747:
		return "LXPRO.COM LinkTest SSL";
	case 3748:
		return "webData";
	case 3749:
		return "CimTrak";
	case 3750:
		return "CBOS/IP ncapsalation port";
	case 3751:
		return "CommLinx GPRS Cube";
	case 3752:
		return "Vigil-IP RemoteAgent";
	case 3753:
		return "NattyServer Port";
	case 3754:
		return "TimesTen Broker Port";
	case 3755:
		return "SAS Remote Help Server";
	case 3756:
		return "Canon CAPT Port";
	case 3757:
		return "GRF Server Port";
	case 3758:
		return "apw RMI registry";
	case 3759:
		return "Exapt License Manager";
	case 3760:
		return "adTempus Client";
	case 3761:
		return "gsakmp port";
	case 3762:
		return "GBS SnapMail Protocol";
	case 3763:
		return "XO Wave Control Port";
	case 3764:
		return "MNI Protected Routing";
	case 3765:
		return "Remote Traceroute";
	case 3766:
		return "SSL e-watch sitewatch server";
	case 3767:
		return "ListMGR Port";
	case 3768:
		return "rblcheckd server daemon";
	case 3769:
		return "HAIPE Network Keying";
	case 3770:
		return "Cinderella Collaboration";
	case 3771:
		return "RTP Paging Port";
	case 3772:
		return "Chantry Tunnel Protocol";
	case 3773:
		return "ctdhercules";
	case 3774:
		return "ZICOM";
	case 3775:
		return "ISPM Manager Port";
	case 3776:
		return "Device Provisioning Port";
	case 3777:
		return "Jibe EdgeBurst";
	case 3778:
		return "Cutler-Hammer IT Port";
	case 3779:
		return "Cognima Replication";
	case 3780:
		return "Nuzzler Network Protocol";
	case 3781:
		return "ABCvoice server port";
	case 3782:
		return "Secure ISO TP0 port";
	case 3783:
		return "Impact Mgr./PEM Gateway";
	case 3784:
		return "BFD Control Protocol";
	case 3785:
		return "BFD Echo Protocol";
	case 3786:
		return "VSW Upstrigger port";
	case 3787:
		return "Fintrx";
	case 3788:
		return "SPACEWAY Routing port";
	case 3789:
		return "RemoteDeploy Administration Port [July 2003]";
	case 3790:
		return "QuickBooks RDS";
	case 3791:
		return "TV NetworkVideo Data port";
	case 3792:
		return "e-Watch Corporation SiteWatch";
	case 3793:
		return "DataCore Software";
	case 3794:
		return "JAUS Robots";
	case 3795:
		return "myBLAST Mekentosj port";
	case 3796:
		return "Spaceway Dialer";
	case 3797:
		return "idps";
	case 3798:
		return "Minilock";
	case 3799:
		return "RADIUS Dynamic Authorization";
	case 3800:
		return "Print Services Interface";
	case 3801:
		return "ibm manager service";
	case 3802:
		return "VHD";
	case 3803:
		return "SoniqSync";
	case 3804:
		return "Harman IQNet Port";
	case 3805:
		return "ThorGuard Server Port";
	case 3806:
		return "Remote System Manager";
	case 3807:
		return "SpuGNA Communication Port";
	case 3808:
		return "Sun App Svr-IIOPClntAuth";
	case 3809:
		return "Java Desktop System Configuration Agent";
	case 3810:
		return "WLAN AS server";
	case 3811:
		return "AMP";
	case 3812:
		return "netO WOL Server";
	case 3813:
		return "Rhapsody Interface Protocol";
	case 3814:
		return "netO DCS";
	case 3815:
		return "LANsurveyor XML";
	case 3816:
		return "Sun Local Patch Server";
	case 3817:
		return "Yosemite Tech Tapeware";
	case 3818:
		return "Crinis Heartbeat";
	case 3819:
		return "EPL Sequ Layer Protocol";
	case 3820:
		return "Siemens AuD SCP";
	case 3821:
		return "ATSC PMCP Standard";
	case 3822:
		return "Compute Pool Discovery";
	case 3823:
		return "Compute Pool Conduit";
	case 3824:
		return "Compute Pool Policy";
	case 3825:
		return "Antera FlowFusion Process Simulation";
	case 3826:
		return "WarMUX game server";
	case 3827:
		return "Netadmin Systems MPI service";
	case 3828:
		return "Netadmin Systems Event Handler";
	case 3829:
		return "Netadmin Systems Event Handler External";
	case 3830:
		return "Cerner System Management Agent";
	case 3831:
		return "Docsvault Application Service";
	case 3832:
		return "xxNETserver";
	case 3833:
		return "AIPN LS Authentication";
	case 3834:
		return "Spectar Data Stream Service";
	case 3835:
		return "Spectar Database Rights Service";
	case 3836:
		return "MARKEM NEXTGEN DCP";
	case 3837:
		return "MARKEM Auto-Discovery";
	case 3838:
		return "Scito Object Server";
	case 3839:
		return "AMX Resource Management Suite";
	case 3840:
		return "www.FlirtMitMir.de";
	case 3841:
		return "ShipRush Database Server";
	case 3842:
		return "NHCI status port";
	case 3843:
		return "Quest Common Agent";
	case 3844:
		return "RNM";
	case 3845:
		return "V-ONE Single Port Proxy";
	case 3846:
		return "Astare Network PCP";
	case 3847:
		return "MS Firewall Control";
	case 3848:
		return "IT Environmental Monitor";
	case 3849:
		return "SPACEWAY DNS Preload";
	case 3850:
		return "QTMS Bootstrap Protocol";
	case 3851:
		return "SpectraTalk Port";
	case 3852:
		return "SSE App Configuration";
	case 3853:
		return "SONY scanning protocol";
	case 3854:
		return "Stryker Comm Port";
	case 3855:
		return "OpenTRAC";
	case 3856:
		return "INFORMER";
	case 3857:
		return "Trap Port";
	case 3858:
		return "Trap Port MOM";
	case 3859:
		return "Navini Port";
	case 3860:
		return "Server/Application State Protocol (SASP)";
	case 3861:
		return "winShadow Host Discovery";
	case 3862:
		return "GIGA-POCKET";
	case 3863:
		return "asap tcp port";
	case 3864:
		return "asap/tls tcp port";
	case 3865:
		return "xpl automation protocol";
	case 3866:
		return "Sun SDViz DZDAEMON Port";
	case 3867:
		return "Sun SDViz DZOGLSERVER Port";
	case 3868:
		return "DIAMETER";
	case 3869:
		return "hp OVSAM MgmtServer Disco";
	case 3870:
		return "hp OVSAM HostAgent Disco";
	case 3871:
		return "Avocent DS Authorization";
	case 3872:
		return "OEM Agent";
	case 3873:
		return "fagordnc";
	case 3874:
		return "SixXS Configuration";
	case 3875:
		return "PNBSCADA";
	case 3876:
		return "DirectoryLockdown Agent IANA assigned this well-formed service name as a replacement for dl_agent.";
	case 3877:
		return "XMPCR Interface Port";
	case 3878:
		return "FotoG CAD interface";
	case 3879:
		return "appss license manager";
	case 3880:
		return "IGRS";
	case 3881:
		return "Data Acquisition and Control";
	case 3882:
		return "DTS Service Port";
	case 3883:
		return "VR Peripheral Network";
	case 3884:
		return "SofTrack Metering";
	case 3885:
		return "TopFlow SSL";
	case 3886:
		return "NEI management port";
	case 3887:
		return "Ciphire Data Transport";
	case 3888:
		return "Ciphire Services";
	case 3889:
		return "D and V Tester Control Port";
	case 3890:
		return "Niche Data Server Connect";
	case 3891:
		return "Oracle RTC-PM port";
	case 3892:
		return "PCC-image-port";
	case 3893:
		return "CGI StarAPI Server";
	case 3894:
		return "SyAM Agent Port";
	case 3895:
		return "SyAm SMC Service Port";
	case 3896:
		return "Simple Distributed Objects over TLS";
	case 3897:
		return "Simple Distributed Objects over SSH";
	case 3898:
		return "IAS";
	case 3899:
		return "ITV Port";
	case 3900:
		return "Unidata UDT OS IANA assigned this well-formed service name as a replacement for udt_os.";
	case 3901:
		return "NIM Service Handler";
	case 3902:
		return "NIMsh Auxiliary Port";
	case 3903:
		return "CharsetMGR";
	case 3904:
		return "Arnet Omnilink Port";
	case 3905:
		return "Mailbox Update (MUPDATE) protocol";
	case 3906:
		return "TopoVista elevation data";
	case 3907:
		return "Imoguia Port";
	case 3908:
		return "HP Procurve NetManagement";
	case 3909:
		return "SurfControl CPA";
	case 3910:
		return "Printer Request Port";
	case 3911:
		return "Printer Status Port";
	case 3912:
		return "Global Maintech Stars";
	case 3913:
		return "ListCREATOR Port";
	case 3914:
		return "ListCREATOR Port 2";
	case 3915:
		return "Auto-Graphics Cataloging";
	case 3916:
		return "WysDM Controller";
	case 3917:
		return "AFT multiplex port";
	case 3918:
		return "PacketCableMultimediaCOPS";
	case 3919:
		return "HyperIP";
	case 3920:
		return "Exasoft IP Port";
	case 3921:
		return "Herodotus Net";
	case 3922:
		return "Soronti Update Port";
	case 3923:
		return "Symbian Service Broker";
	case 3924:
		return "MPL_GPRS_PORT";
	case 3925:
		return "Zoran Media Port";
	case 3926:
		return "WINPort";
	case 3927:
		return "ScsTsr";
	case 3928:
		return "PXE NetBoot Manager";
	case 3929:
		return "AMS Port";
	case 3930:
		return "Syam Web Server Port";
	case 3931:
		return "MSR Plugin Port";
	case 3932:
		return "Dynamic Site System";
	case 3933:
		return "PL/B App Server User Port";
	case 3934:
		return "PL/B File Manager Port";
	case 3935:
		return "SDP Port Mapper Protocol";
	case 3936:
		return "Mailprox";
	case 3937:
		return "DVB Service Discovery";
	case 3938:
		return "Oracle dbControl Agent po IANA assigned this well-formed service name as a replacement for dbcontrol_agent.";
	case 3939:
		return "Anti-virus Application Management Port";
	case 3940:
		return "XeCP Node Service";
	case 3941:
		return "Home Portal Web Server";
	case 3942:
		return "satellite distribution";
	case 3943:
		return "TetraNode Ip Gateway";
	case 3944:
		return "S-Ops Management";
	case 3945:
		return "EMCADS Server Port";
	case 3946:
		return "BackupEDGE Server";
	case 3947:
		return "Connect and Control Protocol for Consumer";
	case 3948:
		return "Anton Paar Device Administration Protocol";
	case 3949:
		return "Dynamic Routing Information Protocol";
	case 3950:
		return "Name Munging";
	case 3951:
		return "PWG IPP Facsimile";
	case 3952:
		return "I3 Session Manager";
	case 3953:
		return "Eydeas XMLink Connect";
	case 3954:
		return "AD Replication RPC";
	case 3955:
		return "p2pCommunity";
	case 3956:
		return "GigE Vision Control";
	case 3957:
		return "MQEnterprise Broker";
	case 3958:
		return "MQEnterprise Agent";
	case 3959:
		return "Tree Hopper Networking";
	case 3960:
		return "Bess Peer Assessment";
	case 3961:
		return "ProAxess Server";
	case 3962:
		return "SBI Agent Protocol";
	case 3963:
		return "Teran Hybrid Routing Protocol";
	case 3964:
		return "SASG GPRS";
	case 3965:
		return "Avanti IP to NCPE API";
	case 3966:
		return "BuildForge Lock Manager";
	case 3967:
		return "PPS Message Service";
	case 3968:
		return "iAnywhere DBNS";
	case 3969:
		return "Landmark Messages";
	case 3970:
		return "LANrev Agent";
	case 3971:
		return "LANrev Server";
	case 3972:
		return "ict-control Protocol";
	case 3973:
		return "ConnectShip Progistics";
	case 3974:
		return "Remote Applicant Tracking Service";
	case 3975:
		return "Air Shot";
	case 3976:
		return "Server Automation Agent";
	case 3977:
		return "Opsware Manager";
	case 3978:
		return "Secured Configuration Server";
	case 3979:
		return "Smith Micro Wide Area Network Service";
	case 3980:
		return "Reserved";
	case 3981:
		return "Starfish System Admin";
	case 3982:
		return "ESRI Image Server";
	case 3983:
		return "ESRI Image Service";
	case 3984:
		return "MAPPER network node manager";
	case 3985:
		return "MAPPER TCP/IP server";
	case 3986:
		return "MAPPER workstation server IANA assigned this well-formed service name as a replacement for mapper-ws_ethd.";
	case 3987:
		return "Centerline";
	case 3988:
		return "DCS Configuration Port";
	case 3989:
		return "BindView-Query Engine";
	case 3990:
		return "BindView-IS";
	case 3991:
		return "BindView-SMCServer";
	case 3992:
		return "BindView-DirectoryServer";
	case 3993:
		return "BindView-Agent";
	case 3995:
		return "ISS Management Svcs SSL";
	case 3996:
		return "abcsoftware-01";
	case 3997:
		return "aes_db";
	case 3998:
		return "Distributed Nagios Executor Service";
	case 3999:
		return "Norman distributes scanning service";
	case 4000:
		return "Terabase";
	case 4001:
		return "NewOak";
	case 4002:
		return "pxc-spvr-ft";
	case 4003:
		return "pxc-splr-ft";
	case 4004:
		return "pxc-roid";
	case 4005:
		return "pxc-pin";
	case 4006:
		return "pxc-spvr";
	case 4007:
		return "pxc-splr";
	case 4008:
		return "NetCheque accounting";
	case 4009:
		return "Chimera HWM";
	case 4010:
		return "Samsung Unidex";
	case 4011:
		return "Alternate Service Boot";
	case 4012:
		return "PDA Gate";
	case 4013:
		return "ACL Manager";
	case 4014:
		return "TAICLOCK";
	case 4015:
		return "Talarian Mcast";
	case 4016:
		return "Talarian Mcast";
	case 4017:
		return "Talarian Mcast";
	case 4018:
		return "Talarian Mcast";
	case 4019:
		return "Talarian Mcast";
	case 4020:
		return "TRAP Port";
	case 4021:
		return "Nexus Portal";
	case 4022:
		return "DNOX";
	case 4023:
		return "ESNM Zoning Port";
	case 4024:
		return "TNP1 User Port";
	case 4025:
		return "Partition Image Port";
	case 4026:
		return "Graphical Debug Server";
	case 4027:
		return "bitxpress";
	case 4028:
		return "DTServer Port";
	case 4029:
		return "IP Q signaling protocol";
	case 4030:
		return "Accell/JSP Daemon Port";
	case 4031:
		return "UUCP over SSL";
	case 4032:
		return "VERITAS Authorization Service";
	case 4033:
		return "SANavigator Peer Port";
	case 4034:
		return "Ubiquinox Daemon";
	case 4035:
		return "WAP Push OTA-HTTP port";
	case 4036:
		return "WAP Push OTA-HTTP secure";
	case 4037:
		return "RaveHD network control";
	case 4038:
		return "Fazzt Point-To-Point";
	case 4039:
		return "Fazzt Administration";
	case 4040:
		return "Yo.net main service";
	case 4041:
		return "Rocketeer-Houston";
	case 4042:
		return "LDXP";
	case 4043:
		return "Neighbour Identity Resolution";
	case 4044:
		return "Location Tracking Protocol";
	case 4045:
		return "Network Paging Protocol";
	case 4046:
		return "Accounting Protocol";
	case 4047:
		return "Context Transfer Protocol";
	case 4049:
		return "Wide Area File Services";
	case 4050:
		return "Wide Area File Services";
	case 4051:
		return "Cisco Peer to Peer Distribution Protocol";
	case 4052:
		return "VoiceConnect Interact";
	case 4053:
		return "CosmoCall Universe Communications Port 1";
	case 4054:
		return "CosmoCall Universe Communications Port 2";
	case 4055:
		return "CosmoCall Universe Communications Port 3";
	case 4056:
		return "Location Message Service";
	case 4057:
		return "Servigistics WFM server";
	case 4058:
		return "Kingfisher protocol";
	case 4059:
		return "DLMS/COSEM";
	case 4060:
		return "DSMETER Inter-Agent Transfer Channel IANA assigned this well-formed service name as a replacement for dsmeter_iatc.";
	case 4061:
		return "Ice Location Service (TCP)";
	case 4062:
		return "Ice Location Service (SSL)";
	case 4063:
		return "Ice Firewall Traversal Service (TCP)";
	case 4064:
		return "Ice Firewall Traversal Service (SSL)";
	case 4065:
		return "Avanti Common Data IANA assigned this well-formed service name as a replacement for avanti_cdp.";
	case 4066:
		return "Performance Measurement and Analysis";
	case 4067:
		return "Information Distribution Protocol";
	case 4068:
		return "IP Fleet Broadcast";
	case 4069:
		return "Minger Email Address Validation Service";
	case 4070:
		return "Trivial IP Encryption (TrIPE)";
	case 4071:
		return "Automatically Incremental Backup";
	case 4072:
		return "Zieto Socket Communications";
	case 4073:
		return "Interactive Remote Application Pairing Protocol";
	case 4074:
		return "Cequint City ID UI trigger";
	case 4075:
		return "ISC Alarm Message Service";
	case 4076:
		return "Seraph DCS";
	case 4077:
		return "Reserved";
	case 4078:
		return "Coordinated Security Service Protocol";
	case 4079:
		return "SANtools Diagnostic Server";
	case 4080:
		return "Lorica inside facing";
	case 4081:
		return "Lorica inside facing (SSL)";
	case 4082:
		return "Lorica outside facing";
	case 4083:
		return "Lorica outside facing (SSL)";
	case 4084:
		return "Reserved";
	case 4085:
		return "EZNews Newsroom Message Service";
	case 4086:
		return "Reserved";
	case 4087:
		return "APplus Service";
	case 4088:
		return "Noah Printing Service Protocol";
	case 4089:
		return "OpenCORE Remote Control Service";
	case 4090:
		return "OMA BCAST Service Guide";
	case 4091:
		return "EminentWare Installer";
	case 4092:
		return "EminentWare DGS";
	case 4093:
		return "Pvx Plus CS Host";
	case 4094:
		return "sysrq daemon";
	case 4095:
		return "xtgui information service";
	case 4096:
		return "BRE (Bridge Relay Element)";
	case 4097:
		return "Patrol View";
	case 4098:
		return "drmsfsd";
	case 4099:
		return "DPCP";
	case 4100:
		return "IGo Incognito Data Port";
	case 4101:
		return "Braille protocol";
	case 4102:
		return "Braille protocol";
	case 4103:
		return "Braille protocol";
	case 4104:
		return "Braille protocol";
	case 4105:
		return "Shofar";
	case 4106:
		return "Synchronite";
	case 4107:
		return "JDL Accounting LAN Service";
	case 4108:
		return "ACCEL";
	case 4109:
		return "Instantiated Zero-control Messaging";
	case 4110:
		return "G2 RFID Tag Telemetry Data";
	case 4111:
		return "Xgrid";
	case 4112:
		return "Apple VPN Server Reporting Protocol";
	case 4113:
		return "AIPN LS Registration";
	case 4114:
		return "JomaMQMonitor";
	case 4115:
		return "CDS Transfer Agent";
	case 4116:
		return "smartcard-TLS";
	case 4117:
		return "Hillr Connection Manager";
	case 4118:
		return "Netadmin Systems NETscript service";
	case 4119:
		return "Assuria Log Manager";
	case 4120:
		return "MiniRem Remote Telemetry and Control";
	case 4121:
		return "e-Builder Application Communication";
	case 4122:
		return "Fiber Patrol Alarm Service";
	case 4123:
		return "Z-Wave Protocol";
	case 4124:
		return "Rohill TetraNode Ip Gateway v2";
	case 4125:
		return "Opsview Envoy";
	case 4126:
		return "Data Domain Replication Service";
	case 4127:
		return "NetUniKeyServer";
	case 4128:
		return "NuFW decision delegation protocol";
	case 4129:
		return "NuFW authentication protocol";
	case 4130:
		return "FRONET message protocol";
	case 4131:
		return "Global Maintech Stars";
	case 4132:
		return "NUTS Daemon IANA assigned this well-formed service name as a replacement for nuts_dem.";
	case 4133:
		return "NUTS Bootp Server IANA assigned this well-formed service name as a replacement for nuts_bootp.";
	case 4134:
		return "NIFTY-Serve HMI protocol";
	case 4135:
		return "Classic Line Database Server Attach";
	case 4136:
		return "Classic Line Database Server Request";
	case 4137:
		return "Classic Line Database Server Remote";
	case 4138:
		return "nettest";
	case 4139:
		return "Imperfect Networks Server";
	case 4140:
		return "Cedros Fraud Detection System IANA assigned this well-formed service name as a replacement for cedros_fds.";
	case 4141:
		return "Workflow Server";
	case 4142:
		return "Document Server";
	case 4143:
		return "Document Replication";
	case 4145:
		return "VVR Control";
	case 4146:
		return "TGCConnect Beacon";
	case 4147:
		return "Multum Service Manager";
	case 4148:
		return "HHB Handheld Client";
	case 4149:
		return "A10 GSLB Service";
	case 4150:
		return "PowerAlert Network Shutdown Agent";
	case 4151:
		return "Men & Mice Remote Control IANA assigned this well-formed service name as a replacement for menandmice_noh.";
	case 4152:
		return "iDigTech Multiplex IANA assigned this well-formed service name as a replacement for idig_mux.";
	case 4153:
		return "MBL Remote Battery Monitoring";
	case 4154:
		return "atlinks device discovery";
	case 4155:
		return "Bazaar version control system";
	case 4156:
		return "STAT Results";
	case 4157:
		return "STAT Scanner Control";
	case 4158:
		return "STAT Command Center";
	case 4159:
		return "Network Security Service";
	case 4160:
		return "Jini Discovery";
	case 4161:
		return "OMS Contact";
	case 4162:
		return "OMS Topology";
	case 4163:
		return "Silver Peak Peer Protocol";
	case 4164:
		return "Silver Peak Communication Protocol";
	case 4165:
		return "ArcLink over Ethernet";
	case 4166:
		return "Joost Peer to Peer Protocol";
	case 4167:
		return "DeskDirect Global Network";
	case 4168:
		return "PrintSoft License Server";
	case 4169:
		return "Automation Drive Interface Transport";
	case 4170:
		return "SMPTE Content Synchonization Protocol";
	case 4171:
		return "Maxlogic Supervisor Communication";
	case 4172:
		return "PC over IP";
	case 4173:
		return "Reserved";
	case 4174:
		return "StorMagic Cluster Services";
	case 4175:
		return "Brocade Cluster Communication Protocol";
	case 4176:
		return "Translattice Cluster IPC Proxy";
	case 4177:
		return "Wello P2P pubsub service";
	case 4178:
		return "StorMan";
	case 4179:
		return "Maxum Services";
	case 4180:
		return "HTTPX";
	case 4181:
		return "MacBak";
	case 4182:
		return "Production Company Pro TCP Service";
	case 4183:
		return "CyborgNet communications protocol";
	case 4184:
		return "UNIVERSE SUITE MESSAGE SERVICE IANA assigned this well-formed service name as a replacement for universe_suite.";
	case 4185:
		return "Woven Control Plane Protocol";
	case 4186:
		return "Box Backup Store Service";
	case 4187:
		return "Cascade Proxy IANA assigned this well-formed service name as a replacement for csc_proxy.";
	case 4188:
		return "Vatata Peer to Peer Protocol";
	case 4189:
		return "Path Computation Element Communication Protocol";
	case 4190:
		return "ManageSieve Protocol";
	case 4191:
		return "Reserved";
	case 4192:
		return "Azeti Agent Service";
	case 4193:
		return "PxPlus remote file srvr";
	case 4194:
		return "Security Protocol and Data Model";
	case 4195:
		return "AWS protocol for cloud remoting solution";
	case 4197:
		return "Harman HControl Protocol";
	case 4199:
		return "EIMS ADMIN";
	case 4300:
		return "Corel CCam";
	case 4301:
		return "Diagnostic Data";
	case 4302:
		return "Diagnostic Data Control";
	case 4303:
		return "Simple Railroad Command Protocol";
	case 4304:
		return "One-Wire Filesystem Server";
	case 4305:
		return "better approach to mobile ad-hoc networking";
	case 4306:
		return "Hellgate London";
	case 4307:
		return "TrueConf Videoconference Service";
	case 4308:
		return "CompX-LockView";
	case 4309:
		return "Exsequi Appliance Discovery";
	case 4310:
		return "Mir-RT exchange service";
	case 4311:
		return "P6R Secure Server Management Console";
	case 4312:
		return "Parascale Membership Manager";
	case 4313:
		return "PERRLA User Services";
	case 4314:
		return "ChoiceView Agent";
	case 4316:
		return "ChoiceView Client";
	case 4317:
		return "OpenTelemetry Protocol";
	case 4319:
		return "Fox SkyTale encrypted communication";
	case 4320:
		return "FDT Remote Categorization Protocol";
	case 4321:
		return "Remote Who Is";
	case 4322:
		return "TRIM Event Service";
	case 4323:
		return "TRIM ICE Service";
	case 4325:
		return "Cadcorp GeognoSIS Administrator";
	case 4326:
		return "Cadcorp GeognoSIS";
	case 4327:
		return "Jaxer Web Protocol";
	case 4328:
		return "Jaxer Manager Command Protocol";
	case 4329:
		return "PubliQare Distributed Environment Synchronisation Engine";
	case 4330:
		return "DEY Storage Administration REST API";
	case 4331:
		return "ktickets REST API for event management and ticketing systems (embedded POS devices)";
	case 4332:
		return "Getty Images FOCUS service";
	case 4333:
		return "ArrowHead Service Protocol (AHSP)";
	case 4334:
		return "NETCONF Call Home (SSH)";
	case 4335:
		return "NETCONF Call Home (TLS)";
	case 4336:
		return "RESTCONF Call Home (TLS)";
	case 4340:
		return "Gaia Connector Protocol";
	case 4341:
		return "Reserved";
	case 4342:
		return "Reserved";
	case 4343:
		return "UNICALL";
	case 4344:
		return "VinaInstall";
	case 4345:
		return "Macro 4 Network AS";
	case 4346:
		return "ELAN LM";
	case 4347:
		return "LAN Surveyor";
	case 4348:
		return "ITOSE";
	case 4349:
		return "File System Port Map";
	case 4350:
		return "Net Device";
	case 4351:
		return "PLCY Net Services";
	case 4352:
		return "Projector Link";
	case 4353:
		return "F5 iQuery";
	case 4354:
		return "QSNet Transmitter";
	case 4355:
		return "QSNet Workstation";
	case 4356:
		return "QSNet Assistant";
	case 4357:
		return "QSNet Conductor";
	case 4358:
		return "QSNet Nucleus";
	case 4359:
		return "OMA BCAST Long-Term Key Messages";
	case 4360:
		return "Matrix VNet Communication Protocol IANA assigned this well-formed service name as a replacement for matrix_vnet.";
	case 4361:
		return "Reserved";
	case 4362:
		return "Reserved";
	case 4366:
		return "Reserved";
	case 4368:
		return "WeatherBrief Direct";
	case 4369:
		return "Erlang Port Mapper Daemon";
	case 4370:
		return "ELPRO V2 Protocol Tunnel IANA assigned this well-formed service name as a replacement for elpro_tunnel.";
	case 4371:
		return "LAN2CAN Control";
	case 4372:
		return "LAN2CAN Data";
	case 4373:
		return "Remote Authenticated Command Service";
	case 4374:
		return "PSI Push-to-Talk Protocol";
	case 4375:
		return "Toltec EasyShare";
	case 4376:
		return "BioAPI Interworking";
	case 4377:
		return "Cambridge Pixel SPx Server";
	case 4378:
		return "Cambridge Pixel SPx Display";
	case 4379:
		return "CTDB";
	case 4389:
		return "Xandros Community Management Service";
	case 4390:
		return "Physical Access Control";
	case 4391:
		return "American Printware IMServer Protocol";
	case 4392:
		return "American Printware RXServer Protocol";
	case 4393:
		return "American Printware RXSpooler Protocol";
	case 4394:
		return "Reserved";
	case 4395:
		return "OmniVision communication for Virtual environments";
	case 4396:
		return "Fly Object Space";
	case 4400:
		return "ASIGRA Services";
	case 4401:
		return "ASIGRA Televaulting DS-System Service";
	case 4402:
		return "ASIGRA Televaulting DS-Client Service";
	case 4403:
		return "ASIGRA Televaulting DS-Client Monitoring/Management";
	case 4404:
		return "ASIGRA Televaulting DS-System Monitoring/Management";
	case 4405:
		return "ASIGRA Televaulting Message Level Restore service";
	case 4406:
		return "ASIGRA Televaulting DS-Sleeper Service";
	case 4407:
		return "Network Access Control Agent";
	case 4408:
		return "SLS Technology Control Centre";
	case 4409:
		return "Net-Cabinet comunication";
	case 4410:
		return "RIB iTWO Application Server";
	case 4411:
		return "Found Messaging Protocol";
	case 4412:
		return "Reserved";
	case 4413:
		return "AVI Systems NMS";
	case 4414:
		return "Updog Monitoring and Status Framework";
	case 4415:
		return "Brocade Virtual Router Request";
	case 4416:
		return "PJJ Media Player";
	case 4417:
		return "Workflow Director Communication";
	case 4418:
		return "Reserved";
	case 4419:
		return "Colnod Binary Protocol";
	case 4420:
		return "NVM Express over Fabrics storage access";
	case 4421:
		return "Multi-Platform Remote Management for Cloud Infrastructure";
	case 4422:
		return "TSEP Installation Service Protocol";
	case 4423:
		return "thingkit secure mesh";
	case 4425:
		return "NetROCKEY6 SMART Plus Service";
	case 4426:
		return "SMARTS Beacon Port";
	case 4427:
		return "Drizzle database server";
	case 4428:
		return "OMV-Investigation Server-Client";
	case 4429:
		return "OMV Investigation Agent-Server";
	case 4430:
		return "REAL SQL Server";
	case 4431:
		return "adWISE Pipe";
	case 4432:
		return "L-ACOUSTICS management";
	case 4433:
		return "Versile Object Protocol";
	case 4441:
		return "Reserved";
	case 4442:
		return "Saris";
	case 4443:
		return "Pharos";
	case 4444:
		return "KRB524";
	case 4445:
		return "UPNOTIFYP";
	case 4446:
		return "N1-FWP";
	case 4447:
		return "N1-RMGMT";
	case 4448:
		return "ASC Licence Manager";
	case 4449:
		return "PrivateWire";
	case 4450:
		return "Common ASCII Messaging Protocol";
	case 4451:
		return "CTI System Msg";
	case 4452:
		return "CTI Program Load";
	case 4453:
		return "NSS Alert Manager";
	case 4454:
		return "NSS Agent Manager";
	case 4455:
		return "PR Chat User";
	case 4456:
		return "PR Chat Server";
	case 4457:
		return "PR Register";
	case 4458:
		return "Matrix Configuration Protocol";
	case 4460:
		return "Network Time Security Key Establishment";
	case 4484:
		return "hpssmgmt service";
	case 4485:
		return "Assyst Data Repository Service";
	case 4486:
		return "Integrated Client Message Service";
	case 4487:
		return "Protocol for Remote Execution over TCP";
	case 4488:
		return "Apple Wide Area Connectivity Service ICE Bootstrap";
	case 4500:
		return "IPsec NAT-Traversal";
	case 4534:
		return "Reserved";
	case 4535:
		return "Event Heap Server";
	case 4536:
		return "Event Heap Server SSL";
	case 4537:
		return "WSS Security Service";
	case 4538:
		return "Software Data Exchange Gateway";
	case 4545:
		return "WorldScores";
	case 4546:
		return "SF License Manager (Sentinel)";
	case 4547:
		return "Lanner License Manager";
	case 4548:
		return "Synchromesh";
	case 4549:
		return "Aegate PMR Service";
	case 4550:
		return "Perman I Interbase Server";
	case 4551:
		return "MIH Services";
	case 4552:
		return "Men and Mice Monitoring";
	case 4553:
		return "ICS host services";
	case 4554:
		return "MS FRS Replication";
	case 4555:
		return "RSIP Port";
	case 4556:
		return "DTN Bundle TCP CL Protocol";
	case 4557:
		return "Reserved";
	case 4558:
		return "Reserved";
	case 4559:
		return "HylaFAX";
	case 4563:
		return "Amahi Anywhere";
	case 4566:
		return "Kids Watch Time Control Service";
	case 4567:
		return "TRAM";
	case 4568:
		return "BMC Reporting";
	case 4569:
		return "Inter-Asterisk eXchange";
	case 4570:
		return "Service to distribute and update within a site deployment information for Oracle Communications Suite";
	case 4573:
		return "A port for communication between a server and client for a custom backup system";
	case 4590:
		return "RID over HTTP/TLS";
	case 4591:
		return "HRPD L3T (AT-AN)";
	case 4592:
		return "Reserved";
	case 4593:
		return "IPT (ANRI-ANRI)";
	case 4594:
		return "IAS-Session (ANRI-ANRI)";
	case 4595:
		return "IAS-Paging (ANRI-ANRI)";
	case 4596:
		return "IAS-Neighbor (ANRI-ANRI)";
	case 4597:
		return "A21 (AN-1xBS)";
	case 4598:
		return "A16 (AN-AN)";
	case 4599:
		return "A17 (AN-AN)";
	case 4600:
		return "Piranha1";
	case 4601:
		return "Piranha2";
	case 4602:
		return "EAX MTS Server";
	case 4603:
		return "Men & Mice Upgrade Agent";
	case 4604:
		return "Identity Registration Protocol";
	case 4605:
		return "Direct End to End Secure Chat Protocol";
	case 4606:
		return "Secure ID to IP registration and lookup";
	case 4621:
		return "Reserved";
	case 4646:
		return "Distributed Denial-of-Service Open Threat Signaling (DOTS) Signal Channel Protocol. The service name is used to construct the SRV service names _dots-signal._udp and _dots-signal._tcp for discovering DOTS servers used to establish DOTS signal channel.";
	case 4658:
		return "PlayStation2 App Port";
	case 4659:
		return "PlayStation2 Lobby Port";
	case 4660:
		return "smaclmgr";
	case 4661:
		return "Kar2ouche Peer location service";
	case 4662:
		return "OrbitNet Message Service";
	case 4663:
		return "Note It! Message Service";
	case 4664:
		return "Rimage Messaging Server";
	case 4665:
		return "Container Client Message Service";
	case 4666:
		return "E-Port Message Service";
	case 4667:
		return "MMA Comm Services";
	case 4668:
		return "MMA EDS Service";
	case 4669:
		return "E-Port Data Service";
	case 4670:
		return "Light packets transfer protocol";
	case 4671:
		return "Bull RSF action server";
	case 4672:
		return "remote file access server";
	case 4673:
		return "CXWS Operations";
	case 4674:
		return "AppIQ Agent Management";
	case 4675:
		return "BIAP Device Status";
	case 4676:
		return "BIAP Generic Alert";
	case 4677:
		return "Business Continuity Servi";
	case 4678:
		return "boundary traversal";
	case 4679:
		return "MGE UPS Supervision";
	case 4680:
		return "MGE UPS Management";
	case 4681:
		return "Parliant Telephony System";
	case 4682:
		return "finisar";
	case 4683:
		return "Spike Clipboard Service";
	case 4684:
		return "RFID Reader Protocol 1.0";
	case 4685:
		return "Autopac Protocol";
	case 4686:
		return "Manina Service Protocol";
	case 4687:
		return "Network Scanner Tool FTP";
	case 4688:
		return "Mobile P2P Service";
	case 4689:
		return "Altova DatabaseCentral";
	case 4690:
		return "Prelude IDS message proto";
	case 4691:
		return "monotone Netsync Protocol";
	case 4692:
		return "Conspiracy messaging";
	case 4700:
		return "NetXMS Agent";
	case 4701:
		return "NetXMS Management";
	case 4702:
		return "NetXMS Server Synchronization";
	case 4703:
		return "Network Performance Quality Evaluation System Test Service";
	case 4704:
		return "Assuria Insider";
	case 4711:
		return "Trinity Trust Network Node Communication";
	case 4725:
		return "TruckStar Service";
	case 4726:
		return "Reserved";
	case 4727:
		return "F-Link Client Information Service";
	case 4728:
		return "CA Port Multiplexer";
	case 4729:
		return "Reserved";
	case 4730:
		return "Gearman Job Queue System";
	case 4731:
		return "Remote Capture Protocol";
	case 4732:
		return "Reserved";
	case 4733:
		return "RES Orchestration Catalog Services";
	case 4737:
		return "IPDR/SP";
	case 4738:
		return "SoleraTec Locator";
	case 4739:
		return "IP Flow Info Export";
	case 4740:
		return "ipfix protocol over TLS";
	case 4741:
		return "Luminizer Manager";
	case 4742:
		return "SICCT";
	case 4743:
		return "openhpi HPI service";
	case 4744:
		return "Internet File Synchronization Protocol";
	case 4745:
		return "Funambol Mobile Push";
	case 4746:
		return "Reserved";
	case 4747:
		return "Reserved";
	case 4749:
		return "Profile for Mac";
	case 4750:
		return "Simple Service Auto Discovery";
	case 4751:
		return "Simple Policy Control Protocol";
	case 4752:
		return "Simple Network Audio Protocol";
	case 4753:
		return "Simple Invocation of Methods Over Network (SIMON)";
	case 4754:
		return "Reserved";
	case 4755:
		return "Reserved";
	case 4756:
		return "Reticle Decision Center";
	case 4774:
		return "Converge RPC";
	case 4784:
		return "BFD Multihop Control";
	case 4785:
		return "Reserved";
	case 4786:
		return "Smart Install Service";
	case 4787:
		return "Service Insertion Architecture (SIA) Control-Plane";
	case 4788:
		return "eXtensible Messaging Client Protocol";
	case 4789:
		return "Reserved";
	case 4790:
		return "Reserved";
	case 4791:
		return "Reserved";
	case 4792:
		return "IP Routable Unified Bus";
	case 4800:
		return "Icona Instant Messenging System";
	case 4801:
		return "Icona Web Embedded Chat";
	case 4802:
		return "Icona License System Server";
	case 4803:
		return "Notateit Messaging";
	case 4804:
		return "Reserved";
	case 4827:
		return "HTCP";
	case 4837:
		return "Varadero-0";
	case 4838:
		return "Varadero-1";
	case 4839:
		return "Varadero-2";
	case 4840:
		return "OPC UA Connection Protocol";
	case 4841:
		return "QUOSA Virtual Library Service";
	case 4842:
		return "nCode ICE-flow Library AppServer";
	case 4843:
		return "OPC UA TCP Protocol over TLS/SSL";
	case 4844:
		return "nCode ICE-flow Library LogServer";
	case 4845:
		return "WordCruncher Remote Library Service";
	case 4846:
		return "Contamac ICM Service IANA assigned this well-formed service name as a replacement for contamac_icm.";
	case 4847:
		return "Web Fresh Communication";
	case 4848:
		return "App Server - Admin HTTP";
	case 4849:
		return "App Server - Admin HTTPS";
	case 4850:
		return "Sun App Server - NA";
	case 4851:
		return "Apache Derby Replication";
	case 4867:
		return "Unify Debugger";
	case 4868:
		return "Photon Relay";
	case 4869:
		return "Photon Relay Debug";
	case 4870:
		return "Citcom Tracking Service";
	case 4871:
		return "Wired";
	case 4876:
		return "Tritium CAN Bus Bridge Service";
	case 4877:
		return "Lighting Management Control System";
	case 4878:
		return "Reserved";
	case 4879:
		return "WSDL Event Receiver";
	case 4880:
		return "IVI High-Speed LAN Instrument Protocol";
	case 4881:
		return "Reserved";
	case 4882:
		return "Reserved";
	case 4883:
		return "Meier-Phelps License Server";
	case 4884:
		return "HiveStor Distributed File System";
	case 4885:
		return "ABBS";
	case 4888:
		return "xcap code analysis portal public user access";
	case 4889:
		return "xcap code analysis portal cluster control and administration";
	case 4894:
		return "LysKOM Protocol A";
	case 4899:
		return "RAdmin Port";
	case 4900:
		return "HFSQL Client/Server Database Engine";
	case 4901:
		return "FileLocator Remote Search Agent IANA assigned this well-formed service name as a replacement for flr_agent.";
	case 4902:
		return "magicCONROL RF and Data Interface";
	case 4912:
		return "Technicolor LUT Access Protocol";
	case 4913:
		return "LUTher Control Protocol";
	case 4914:
		return "Bones Remote Control";
	case 4915:
		return "Fibics Remote Control Service";
	case 4936:
		return "Reserved";
	case 4937:
		return "Reserved";
	case 4940:
		return "Equitrac Office";
	case 4941:
		return "Equitrac Office";
	case 4942:
		return "Equitrac Office";
	case 4949:
		return "Munin Graphing Framework";
	case 4950:
		return "Sybase Server Monitor";
	case 4951:
		return "PWG WIMS";
	case 4952:
		return "SAG Directory Server";
	case 4953:
		return "Synchronization Arbiter";
	case 4969:
		return "CCSS QMessageMonitor";
	case 4970:
		return "CCSS QSystemMonitor";
	case 4971:
		return "BackUp and Restore Program";
	case 4980:
		return "Reserved";
	case 4984:
		return "WebYast";
	case 4985:
		return "GER HC Standard";
	case 4986:
		return "Model Railway Interface Program";
	case 4987:
		return "SMAR Ethernet Port 1";
	case 4988:
		return "SMAR Ethernet Port 2";
	case 4989:
		return "Parallel for GAUSS (tm)";
	case 4990:
		return "BusySync Calendar Synch. Protocol";
	case 4991:
		return "VITA Radio Transport";
	case 4999:
		return "HFSQL Client/Server Database Engine Manager";
	case 5000:
		return "";
	case 5001:
		return "";
	case 5002:
		return "radio free ethernet";
	case 5003:
		return "FileMaker";
	case 5004:
		return "RTP media data";
	case 5005:
		return "RTP control protocol";
	case 5006:
		return "wsm server";
	case 5007:
		return "wsm server ssl";
	case 5008:
		return "Synapsis EDGE";
	case 5009:
		return "Microsoft Windows Filesystem";
	case 5010:
		return "TelepathStart";
	case 5011:
		return "TelepathAttack";
	case 5012:
		return "NetOnTap Service";
	case 5013:
		return "FileMaker";
	case 5014:
		return "Reserved";
	case 5015:
		return "FileMaker";
	case 5020:
		return "zenginkyo-1";
	case 5021:
		return "zenginkyo-2";
	case 5022:
		return "mice server";
	case 5023:
		return "Htuil Server for PLD2";
	case 5024:
		return "SCPI-TELNET";
	case 5025:
		return "SCPI-RAW";
	case 5026:
		return "Storix I/O daemon (data)";
	case 5027:
		return "Storix I/O daemon (stat)";
	case 5028:
		return "Quiqum Virtual Relais";
	case 5029:
		return "Infobright Database Server";
	case 5030:
		return "Reserved";
	case 5031:
		return "Reserved";
	case 5032:
		return "SignaCert Enterprise Trust Server Agent";
	case 5033:
		return "Janstor Secure Data";
	case 5034:
		return "Janstor Status";
	case 5042:
		return "asnaacceler8db";
	case 5043:
		return "ShopWorX Administration";
	case 5044:
		return "LXI Event Service";
	case 5045:
		return "Open Settlement Protocol";
	case 5046:
		return "Reserved";
	case 5047:
		return "Reserved";
	case 5048:
		return "Texai Message Service";
	case 5049:
		return "iVocalize Web Conference";
	case 5050:
		return "multimedia conference control tool";
	case 5051:
		return "ITA Agent";
	case 5052:
		return "ITA Manager";
	case 5053:
		return "RLM License Server";
	case 5054:
		return "RLM administrative interface";
	case 5055:
		return "UNOT";
	case 5056:
		return "Intecom Pointspan 1";
	case 5057:
		return "Intecom Pointspan 2";
	case 5058:
		return "Reserved";
	case 5059:
		return "SIP Directory Services";
	case 5060:
		return "SIP";
	case 5061:
		return "SIP-TLS";
	case 5062:
		return "Localisation access";
	case 5063:
		return "centrify secure RPC";
	case 5064:
		return "Channel Access 1";
	case 5065:
		return "Channel Access 2";
	case 5066:
		return "STANAG-5066-SUBNET-INTF";
	case 5067:
		return "Authentx Service";
	case 5068:
		return "Bitforest Data Service";
	case 5069:
		return "I/Net 2000-NPR";
	case 5070:
		return "VersaTrans Server Agent Service";
	case 5071:
		return "PowerSchool";
	case 5072:
		return "Anything In Anything";
	case 5073:
		return "Advantage Group Port Mgr";
	case 5074:
		return "ALES Query";
	case 5075:
		return "Experimental Physics and Industrial Control System";
	case 5078:
		return "Reserved";
	case 5079:
		return "Reserved";
	case 5080:
		return "OnScreen Data Collection Service";
	case 5081:
		return "SDL - Ent Trans Server";
	case 5082:
		return "Qpur Communication Protocol";
	case 5083:
		return "Qpur File Protocol";
	case 5084:
		return "EPCglobal Low-Level Reader Protocol";
	case 5085:
		return "EPCglobal Encrypted LLRP";
	case 5086:
		return "Aprigo Collection Service";
	case 5087:
		return "BIOTIC - Binary Internet of Things Interoperable Communication";
	case 5092:
		return "Reserved";
	case 5093:
		return "Sentinel LM";
	case 5094:
		return "HART-IP";
	case 5099:
		return "SentLM Srv2Srv";
	case 5100:
		return "Socalia service mux";
	case 5101:
		return "Talarian_TCP";
	case 5102:
		return "Oracle OMS non-secure";
	case 5103:
		return "Actifio C2C";
	case 5104:
		return "Reserved";
	case 5105:
		return "Reserved";
	case 5106:
		return "Actifio UDS Agent";
	case 5107:
		return "Disk to Disk replication between Actifio Clusters";
	case 5111:
		return "TAEP AS service";
	case 5112:
		return "PeerMe Msg Cmd Service";
	case 5114:
		return "Enterprise Vault Services";
	case 5115:
		return "Symantec Autobuild Service";
	case 5116:
		return "Reserved";
	case 5117:
		return "GradeCam Image Processing";
	case 5120:
		return "Barracuda Backup Protocol";
	case 5133:
		return "Policy Commander";
	case 5134:
		return "PP ActivationServer";
	case 5135:
		return "ERP-Scale";
	case 5136:
		return "Reserved";
	case 5137:
		return "MyCTS server port";
	case 5145:
		return "RMONITOR SECURE IANA assigned this well-formed service name as a replacement for rmonitor_secure.";
	case 5146:
		return "Social Alarm Service";
	case 5150:
		return "Ascend Tunnel Management Protocol";
	case 5151:
		return "ESRI SDE Instance IANA assigned this well-formed service name as a replacement for esri_sde.";
	case 5152:
		return "ESRI SDE Instance Discovery";
	case 5153:
		return "Reserved";
	case 5154:
		return "BZFlag game server";
	case 5155:
		return "Oracle asControl Agent";
	case 5156:
		return "Russian Online Game";
	case 5157:
		return "Mediat Remote Object Exchange";
	case 5161:
		return "SNMP over SSH Transport Model";
	case 5162:
		return "SNMP Notification over SSH Transport Model";
	case 5163:
		return "Shadow Backup";
	case 5164:
		return "Virtual Protocol Adapter";
	case 5165:
		return "ife_1corp IANA assigned this well-formed service name as a replacement for ife_icorp.";
	case 5166:
		return "WinPCS Service Connection";
	case 5167:
		return "SCTE104 Connection";
	case 5168:
		return "SCTE30 Connection";
	case 5172:
		return "PC over IP Endpoint Management";
	case 5190:
		return "America-Online";
	case 5191:
		return "AmericaOnline1";
	case 5192:
		return "AmericaOnline2";
	case 5193:
		return "AmericaOnline3";
	case 5194:
		return "CipherPoint Config Service";
	case 5195:
		return "The protocol is used by a license server and client programs to control use of program licenses that float to networked machines";
	case 5196:
		return "The protocol is used by two programs that exchange table data used in the AMPL modeling language";
	case 5197:
		return "Tunstall Lone worker device interface";
	case 5200:
		return "TARGUS GetData";
	case 5201:
		return "TARGUS GetData 1";
	case 5202:
		return "TARGUS GetData 2";
	case 5203:
		return "TARGUS GetData 3";
	case 5209:
		return "Nomad Device Video Transfer";
	case 5215:
		return "NOTEZA Data Safety Service";
	case 5221:
		return "3eTI Extensible Management Protocol for OAMP";
	case 5222:
		return "XMPP Client Connection";
	case 5223:
		return "HP Virtual Machine Group Management";
	case 5224:
		return "HP Virtual Machine Console Operations";
	case 5225:
		return "HP Server";
	case 5226:
		return "HP Status";
	case 5227:
		return "HP System Performance Metric Service";
	case 5228:
		return "HP Virtual Room Service";
	case 5229:
		return "Netflow/IPFIX/sFlow Collector and Forwarder Management";
	case 5230:
		return "JaxMP RealFlow application and protocol data";
	case 5231:
		return "Remote Control of Scan Software for Cruse Scanners";
	case 5232:
		return "Cruse Scanning System Service";
	case 5233:
		return "Etinnae Network File Service";
	case 5234:
		return "EEnet communications";
	case 5235:
		return "Galaxy Network Service";
	case 5236:
		return "";
	case 5237:
		return "m-net discovery";
	case 5242:
		return "ATTUne API";
	case 5243:
		return "xyClient Status API and rendevous point";
	case 5245:
		return "DownTools Control Protocol";
	case 5246:
		return "Reserved";
	case 5247:
		return "Reserved";
	case 5248:
		return "CA Access Control Web Service";
	case 5249:
		return "CA AC Lang Service";
	case 5250:
		return "soaGateway";
	case 5251:
		return "CA eTrust VM Service";
	case 5252:
		return "Movaz SSC";
	case 5253:
		return "Kohler Power Device Protocol";
	case 5254:
		return "LogCabin storage service";
	case 5264:
		return "3Com Network Jack Port 1";
	case 5265:
		return "3Com Network Jack Port 2";
	case 5269:
		return "XMPP Server Connection";
	case 5270:
		return "Cartographer XMP";
	case 5271:
		return "StageSoft CueLink messaging";
	case 5272:
		return "PK";
	case 5280:
		return "Bidirectional-streams Over Synchronous HTTP (BOSH)";
	case 5281:
		return "Undo License Manager";
	case 5282:
		return "Marimba Transmitter Port";
	case 5298:
		return "XMPP Link-Local Messaging";
	case 5299:
		return "NLG Data Service";
	case 5300:
		return "HA cluster heartbeat";
	case 5301:
		return "HA cluster general services";
	case 5302:
		return "HA cluster configuration";
	case 5303:
		return "HA cluster probing";
	case 5304:
		return "HA Cluster Commands";
	case 5305:
		return "HA Cluster Test";
	case 5306:
		return "Sun MC Group";
	case 5307:
		return "SCO AIP";
	case 5308:
		return "CFengine";
	case 5309:
		return "J Printer";
	case 5310:
		return "Outlaws";
	case 5312:
		return "Permabit Client-Server";
	case 5313:
		return "Real-time & Reliable Data";
	case 5314:
		return "opalis-rbt-ipc";
	case 5315:
		return "HA Cluster UDP Polling";
	case 5316:
		return "HPBladeSystem Monitor Service";
	case 5317:
		return "HP Device Monitor Service";
	case 5318:
		return "PKIX Certificate Management using CMS (CMC)";
	case 5320:
		return "Webservices-based Zn interface of BSF";
	case 5321:
		return "Webservices-based Zn interface of BSF over SSL";
	case 5343:
		return "Sculptor Database Server";
	case 5344:
		return "xkoto DRCP";
	case 5349:
		return "Session Traversal Utilities for NAT (STUN) port";
	case 5350:
		return "Reserved";
	case 5351:
		return "Reserved";
	case 5352:
		return "DNS Long-Lived Queries";
	case 5353:
		return "Multicast DNS";
	case 5354:
		return "Multicast DNS Responder IPC";
	case 5355:
		return "LLMNR";
	case 5356:
		return "Microsoft Small Business";
	case 5357:
		return "Web Services for Devices";
	case 5358:
		return "WS for Devices Secured";
	case 5359:
		return "Microsoft Alerter";
	case 5360:
		return "Protocol for Windows SideShow";
	case 5361:
		return "Secure Protocol for Windows SideShow";
	case 5362:
		return "Microsoft Windows Server WSD2 Service";
	case 5363:
		return "Windows Network Projection";
	case 5364:
		return "Reserved";
	case 5397:
		return "StressTester(tm) Injector";
	case 5398:
		return "Elektron Administration";
	case 5399:
		return "SecurityChase";
	case 5400:
		return "Excerpt Search";
	case 5401:
		return "Excerpt Search Secure";
	case 5402:
		return "OmniCast MFTP";
	case 5403:
		return "HPOMS-CI-LSTN";
	case 5404:
		return "HPOMS-DPS-LSTN";
	case 5405:
		return "NetSupport";
	case 5406:
		return "Systemics Sox";
	case 5407:
		return "Foresyte-Clear";
	case 5408:
		return "Foresyte-Sec";
	case 5409:
		return "Salient Data Server";
	case 5410:
		return "Salient User Manager";
	case 5411:
		return "ActNet";
	case 5412:
		return "Continuus";
	case 5413:
		return "WWIOTALK";
	case 5414:
		return "StatusD";
	case 5415:
		return "NS Server";
	case 5416:
		return "SNS Gateway";
	case 5417:
		return "SNS Agent";
	case 5418:
		return "MCNTP";
	case 5419:
		return "DJ-ICE";
	case 5420:
		return "Cylink-C";
	case 5421:
		return "Net Support 2";
	case 5422:
		return "Salient MUX";
	case 5423:
		return "VIRTUALUSER";
	case 5424:
		return "Beyond Remote";
	case 5425:
		return "Beyond Remote Command Channel";
	case 5426:
		return "DEVBASIC";
	case 5427:
		return "SCO-PEER-TTA";
	case 5428:
		return "TELACONSOLE";
	case 5429:
		return "Billing and Accounting System Exchange";
	case 5430:
		return "RADEC CORP";
	case 5431:
		return "PARK AGENT";
	case 5432:
		return "PostgreSQL Database";
	case 5433:
		return "Pyrrho DBMS";
	case 5434:
		return "SGI Array Services Daemon";
	case 5435:
		return "SCEANICS situation and action notification";
	case 5436:
		return "Reserved";
	case 5437:
		return "Reserved";
	case 5443:
		return "Pearson HTTPS";
	case 5445:
		return "Server Message Block over Remote Direct Memory Access";
	case 5450:
		return "TiePie engineering data acquisition";
	case 5453:
		return "SureBox";
	case 5454:
		return "APC 5454";
	case 5455:
		return "APC 5455";
	case 5456:
		return "APC 5456";
	case 5461:
		return "SILKMETER";
	case 5462:
		return "TTL Publisher";
	case 5463:
		return "TTL Price Proxy";
	case 5464:
		return "Quail Networks Object Broker";
	case 5465:
		return "NETOPS-BROKER";
	case 5470:
		return "The Apsolab company's data collection protocol (native api)";
	case 5471:
		return "The Apsolab company's secure data collection protocol (native api)";
	case 5472:
		return "The Apsolab company's dynamic tag protocol";
	case 5473:
		return "The Apsolab company's secure dynamic tag protocol";
	case 5474:
		return "Reserved";
	case 5475:
		return "The Apsolab company's data retrieval protocol";
	case 5500:
		return "fcp-addr-srvr1";
	case 5501:
		return "fcp-addr-srvr2";
	case 5502:
		return "fcp-srvr-inst1";
	case 5503:
		return "fcp-srvr-inst2";
	case 5504:
		return "fcp-cics-gw1";
	case 5505:
		return "Checkout Database";
	case 5506:
		return "Amcom Mobile Connect";
	case 5507:
		return "PowerSysLab Electrical Management";
	case 5540:
		return "Matter Operational Discovery and Communi";
	case 5550:
		return "Model Railway control using the CBUS message protocol";
	case 5553:
		return "SGI Eventmond Port";
	case 5554:
		return "SGI ESP HTTP";
	case 5555:
		return "Personal Agent";
	case 5556:
		return "Freeciv gameplay";
	case 5557:
		return "Sandlab FARENET";
	case 5565:
		return "Data Protector BURA";
	case 5566:
		return "Westec Connect";
	case 5567:
		return "DOF Protocol Stack Multicast/Secure Transport";
	case 5568:
		return "Session Data Transport Multicast";
	case 5569:
		return "PLASA E1.33";
	case 5573:
		return "SAS Domain Management Messaging Protocol";
	case 5574:
		return "SAS IO Forwarding";
	case 5575:
		return "Oracle Access Protocol";
	case 5579:
		return "FleetDisplay Tracking Service";
	case 5580:
		return "T-Mobile SMS Protocol Message 0";
	case 5581:
		return "T-Mobile SMS Protocol Message 1";
	case 5582:
		return "T-Mobile SMS Protocol Message 3";
	case 5583:
		return "T-Mobile SMS Protocol Message 2";
	case 5584:
		return "BeInSync-Web";
	case 5585:
		return "BeInSync-sync";
	case 5586:
		return "Planning to send mobile terminated SMS to the specific port so that the SMS is not visible to the client";
	case 5597:
		return "inin secure messaging";
	case 5598:
		return "MCT Market Data Feed";
	case 5599:
		return "Enterprise Security Remote Install";
	case 5600:
		return "Enterprise Security Manager";
	case 5601:
		return "Enterprise Security Agent";
	case 5602:
		return "A1-MSC";
	case 5603:
		return "A1-BS";
	case 5604:
		return "A3-SDUNode";
	case 5605:
		return "A4-SDUNode";
	case 5618:
		return "Fiscal Registering Protocol";
	case 5627:
		return "Node Initiated Network Association Forma";
	case 5628:
		return "HTrust API";
	case 5629:
		return "Symantec Storage Foundation for Database";
	case 5630:
		return "PreciseCommunication";
	case 5631:
		return "pcANYWHEREdata";
	case 5632:
		return "pcANYWHEREstat";
	case 5633:
		return "BE Operations Request Listener";
	case 5634:
		return "SF Message Service";
	case 5635:
		return "SFM Authentication Subsystem";
	case 5636:
		return "SFMdb - SFM DB server";
	case 5637:
		return "Symantec CSSC";
	case 5638:
		return "Symantec Fingerprint Lookup and Container Reference Service";
	case 5639:
		return "Symantec Integrity Checking Service";
	case 5646:
		return "Ventureforth Mobile";
	case 5666:
		return "Nagios Remote Plugin Executor";
	case 5670:
		return "ZeroMQ file publish-subscribe protocol";
	case 5671:
		return "amqp protocol over TLS/SSL";
	case 5672:
		return "AMQP";
	case 5673:
		return "JACL Message Server";
	case 5674:
		return "HyperSCSI Port";
	case 5675:
		return "V5UA application port";
	case 5676:
		return "RA Administration";
	case 5677:
		return "Quest Central DB2 Launchr";
	case 5678:
		return "Remote Replication Agent Connection";
	case 5679:
		return "Direct Cable Connect Manager";
	case 5680:
		return "Auriga Router Service";
	case 5681:
		return "Net-coneX Control Protocol";
	case 5682:
		return "Reserved";
	case 5683:
		return "Constrained Application Protocol (CoAP)";
	case 5684:
		return "Constrained Application Protocol (CoAP)";
	case 5687:
		return "Reserved";
	case 5688:
		return "GGZ Gaming Zone";
	case 5689:
		return "QM video network management protocol";
	case 5693:
		return "Robert Bosch Data Transfer";
	case 5696:
		return "Key Management Interoperability Protocol";
	case 5700:
		return "Dell SupportAssist data center management";
	case 5705:
		return "StorageOS REST API";
	case 5713:
		return "proshare conf audio";
	case 5714:
		return "proshare conf video";
	case 5715:
		return "proshare conf data";
	case 5716:
		return "proshare conf request";
	case 5717:
		return "proshare conf notify";
	case 5718:
		return "DPM Communication Server";
	case 5719:
		return "DPM Agent Coordinator";
	case 5720:
		return "MS-Licensing";
	case 5721:
		return "Desktop Passthru Service";
	case 5722:
		return "Microsoft DFS Replication Service";
	case 5723:
		return "Operations Manager - Health Service";
	case 5724:
		return "Operations Manager - SDK Service";
	case 5725:
		return "Microsoft Identity Lifecycle Manager";
	case 5726:
		return "Microsoft Lifecycle Manager Secure Token Service";
	case 5727:
		return "ASG Event Notification Framework";
	case 5728:
		return "Dist. I/O Comm. Service Data and Control";
	case 5729:
		return "Openmail User Agent Layer";
	case 5730:
		return "Steltor's calendar access";
	case 5741:
		return "IDA Discover Port 1";
	case 5742:
		return "IDA Discover Port 2";
	case 5743:
		return "Watchdoc NetPOD Protocol";
	case 5744:
		return "Watchdoc Server";
	case 5745:
		return "fcopy-server";
	case 5746:
		return "fcopys-server";
	case 5747:
		return "Wildbits Tunatic";
	case 5748:
		return "Wildbits Tunalyzer";
	case 5750:
		return "Bladelogic Agent Service";
	case 5755:
		return "OpenMail Desk Gateway server";
	case 5757:
		return "OpenMail X.500 Directory Server";
	case 5766:
		return "OpenMail NewMail Server";
	case 5767:
		return "OpenMail Suer Agent Layer (Secure)";
	case 5768:
		return "OpenMail CMTS Server";
	case 5769:
		return "x509solutions Internal CA";
	case 5770:
		return "x509solutions Secure Data";
	case 5771:
		return "NetAgent";
	case 5777:
		return "Control commands and responses";
	case 5780:
		return "Visual Tag System RPC";
	case 5781:
		return "3PAR Event Reporting Service";
	case 5782:
		return "3PAR Management Service";
	case 5783:
		return "3PAR Management Service with SSL";
	case 5784:
		return "Reserved";
	case 5785:
		return "3PAR Inform Remote Copy";
	case 5786:
		return "Reserved";
	case 5787:
		return "Reserved";
	case 5793:
		return "XtreamX Supervised Peer message";
	case 5794:
		return "Reserved";
	case 5798:
		return "Proprietary Website deployment service";
	case 5813:
		return "ICMPD";
	case 5814:
		return "Support Automation";
	case 5820:
		return "AutoPass licensing";
	case 5841:
		return "Z-firm ShipRush interface for web access and bidirectional data";
	case 5842:
		return "Reversion Backup/Restore";
	case 5859:
		return "WHEREHOO";
	case 5863:
		return "PlanetPress Suite Messeng";
	case 5868:
		return "Diameter over TLS/TCP";
	case 5883:
		return "Javascript Unit Test Environment";
	case 5900:
		return "Remote Framebuffer";
	case 5903:
		return "Flight & Flow Info for Collaborative Env";
	case 5904:
		return "Air-Ground SWIM";
	case 5905:
		return "Adv Surface Mvmnt and Guidance Cont Sys";
	case 5906:
		return "Remotely Piloted Vehicle C&C";
	case 5907:
		return "Distress and Safety Data App";
	case 5908:
		return "IPS Management Application";
	case 5909:
		return "Air-ground media advisory";
	case 5910:
		return "Air Traffic Services applications using ATN";
	case 5911:
		return "Air Traffic Services applications using ACARS";
	case 5912:
		return "Aeronautical Information Service/Meteorological applications using ACARS";
	case 5913:
		return "Airline operational communications applications using ACARS";
	case 5963:
		return "Indy Application Server";
	case 5968:
		return "mppolicy-v5";
	case 5969:
		return "mppolicy-mgr";
	case 5984:
		return "CouchDB";
	case 5985:
		return "WBEM WS-Management HTTP";
	case 5986:
		return "WBEM WS-Management HTTP over TLS/SSL";
	case 5987:
		return "WBEM RMI";
	case 5988:
		return "WBEM CIM-XML (HTTP)";
	case 5989:
		return "WBEM CIM-XML (HTTPS)";
	case 5990:
		return "WBEM Export HTTPS";
	case 5991:
		return "NUXSL";
	case 5992:
		return "Consul InSight Security";
	case 5993:
		return "DMTF WBEM CIM REST";
	case 5994:
		return "RMS Agent Listening Service";
	case 5999:
		return "CVSup";
	case 6064:
		return "NDL-AHP-SVC";
	case 6065:
		return "WinPharaoh";
	case 6066:
		return "EWCTSP";
	case 6068:
		return "GSMP/ANCP";
	case 6069:
		return "TRIP";
	case 6070:
		return "Messageasap";
	case 6071:
		return "SSDTP";
	case 6072:
		return "DIAGNOSE-PROC";
	case 6073:
		return "DirectPlay8";
	case 6074:
		return "Microsoft Max";
	case 6075:
		return "Microsoft DPM Access Control Manager";
	case 6076:
		return "Microsoft DPM WCF Certificates";
	case 6077:
		return "iConstruct Server";
	case 6080:
		return "Reserved";
	case 6081:
		return "Reserved";
	case 6082:
		return "Reserved";
	case 6083:
		return "Reserved";
	case 6084:
		return "Peer to Peer Infrastructure Configuration";
	case 6085:
		return "konspire2b p2p network";
	case 6086:
		return "PDTP P2P";
	case 6087:
		return "Local Download Sharing Service";
	case 6088:
		return "SuperDog License Manager";
	case 6099:
		return "RAXA Management";
	case 6100:
		return "SynchroNet-db";
	case 6101:
		return "SynchroNet-rtc";
	case 6102:
		return "SynchroNet-upd";
	case 6103:
		return "RETS";
	case 6104:
		return "DBDB";
	case 6105:
		return "Prima Server";
	case 6106:
		return "MPS Server";
	case 6107:
		return "ETC Control";
	case 6108:
		return "Sercomm-SCAdmin";
	case 6109:
		return "GLOBECAST-ID";
	case 6110:
		return "HP SoftBench CM";
	case 6111:
		return "HP SoftBench Sub-Process Control";
	case 6112:
		return "Desk-Top Sub-Process Control Daemon";
	case 6113:
		return "Daylite Server";
	case 6114:
		return "WRspice IPC Service";
	case 6115:
		return "Xic IPC Service";
	case 6116:
		return "XicTools License Manager Service";
	case 6117:
		return "Daylite Touch Sync";
	case 6118:
		return "Reserved";
	case 6121:
		return "SPDY for a faster web";
	case 6122:
		return "Backup Express Web Server";
	case 6123:
		return "Backup Express";
	case 6124:
		return "Phlexible Network Backup Service";
	case 6130:
		return "The DameWare Mobile Gateway Service";
	case 6133:
		return "New Boundary Tech WOL";
	case 6140:
		return "Pulsonix Network License Service";
	case 6141:
		return "Meta Corporation License Manager";
	case 6142:
		return "Aspen Technology License Manager";
	case 6143:
		return "Watershed License Manager";
	case 6144:
		return "StatSci License Manager - 1";
	case 6145:
		return "StatSci License Manager - 2";
	case 6146:
		return "Lone Wolf Systems License Manager";
	case 6147:
		return "Montage License Manager";
	case 6148:
		return "Ricardo North America License Manager";
	case 6149:
		return "tal-pod";
	case 6159:
		return "EFB Application Control Interface";
	case 6160:
		return "Emerson Extensible Control and Management Protocol";
	case 6161:
		return "PATROL Internet Srv Mgr";
	case 6162:
		return "PATROL Collector";
	case 6163:
		return "Precision Scribe Cnx Port";
	case 6200:
		return "LM-X License Manager by X-Formation";
	case 6201:
		return "Reserved";
	case 6209:
		return "QMTP over TLS";
	case 6222:
		return "Radmind Access Protocol";
	case 6241:
		return "JEOL Network Services Data Transport Protocol 1";
	case 6242:
		return "JEOL Network Services Data Transport Protocol 2";
	case 6243:
		return "JEOL Network Services Data Transport Protocol 3";
	case 6244:
		return "JEOL Network Services Data Transport Protocol 4";
	case 6251:
		return "TL1 Raw Over SSL/TLS";
	case 6252:
		return "TL1 over SSH";
	case 6253:
		return "CRIP";
	case 6267:
		return "GridLAB-D User Interface";
	case 6268:
		return "Grid Authentication";
	case 6269:
		return "Grid Authentication Alt";
	case 6300:
		return "BMC GRX";
	case 6301:
		return "BMC CONTROL-D LDAP SERVER IANA assigned this well-formed service name as a replacement for bmc_ctd_ldap.";
	case 6306:
		return "Unified Fabric Management Protocol";
	case 6315:
		return "Sensor Control Unit Protocol";
	case 6316:
		return "Ethernet Sensor Communications Protocol";
	case 6317:
		return "Navtech Radar Sensor Data Command";
	case 6320:
		return "Double-Take Replication Service";
	case 6321:
		return "Empress Software Connectivity Server 1";
	case 6322:
		return "Empress Software Connectivity Server 2";
	case 6324:
		return "HR Device Network Configuration Service";
	case 6325:
		return "Double-Take Management Service";
	case 6326:
		return "Double-Take Virtual Recovery Assistant";
	case 6343:
		return "sFlow traffic monitoring";
	case 6344:
		return "Argus-Spectr security and fire-prevention systems service";
	case 6346:
		return "gnutella-svc";
	case 6347:
		return "gnutella-rtr";
	case 6350:
		return "App Discovery and Access Protocol";
	case 6355:
		return "PMCS applications";
	case 6360:
		return "MetaEdit+ Multi-User";
	case 6363:
		return "Reserved";
	case 6370:
		return "MetaEdit+ Server Administration";
	case 6379:
		return "An advanced key-value cache and store";
	case 6382:
		return "Metatude Dialogue Server";
	case 6389:
		return "clariion-evr01";
	case 6390:
		return "MetaEdit+ WebService API";
	case 6417:
		return "Faxcom Message Service";
	case 6418:
		return "SYserver remote commands";
	case 6419:
		return "Simple VDR Protocol";
	case 6420:
		return "NIM_VDRShell";
	case 6421:
		return "NIM_WAN";
	case 6432:
		return "PgBouncer";
	case 6440:
		return "heliosd daemon";
	case 6442:
		return "Transitory Application Request Protocol";
	case 6443:
		return "Service Registry Default HTTPS Domain";
	case 6444:
		return "Grid Engine Qmaster Service IANA assigned this well-formed service name as a replacement for sge_qmaster.";
	case 6445:
		return "Grid Engine Execution Service IANA assigned this well-formed service name as a replacement for sge_execd.";
	case 6446:
		return "MySQL Proxy";
	case 6455:
		return "SKIP Certificate Receive";
	case 6456:
		return "SKIP Certificate Send";
	case 6464:
		return "Port assignment for medical device communication in accordance to IEEE 11073-20701";
	case 6471:
		return "LVision License Manager";
	case 6480:
		return "Service Registry Default HTTP Domain";
	case 6481:
		return "Service Tags";
	case 6482:
		return "Logical Domains Management Interface";
	case 6483:
		return "SunVTS RMI";
	case 6484:
		return "Service Registry Default JMS Domain";
	case 6485:
		return "Service Registry Default IIOP Domain";
	case 6486:
		return "Service Registry Default IIOPS Domain";
	case 6487:
		return "Service Registry Default IIOPAuth Domain";
	case 6488:
		return "Service Registry Default JMX Domain";
	case 6489:
		return "Service Registry Default Admin Domain";
	case 6500:
		return "BoKS Master";
	case 6501:
		return "BoKS Servc IANA assigned this well-formed service name as a replacement for boks_servc.";
	case 6502:
		return "BoKS Servm IANA assigned this well-formed service name as a replacement for boks_servm.";
	case 6503:
		return "BoKS Clntd IANA assigned this well-formed service name as a replacement for boks_clntd.";
	case 6505:
		return "BoKS Admin Private Port IANA assigned this well-formed service name as a replacement for badm_priv.";
	case 6506:
		return "BoKS Admin Public Port IANA assigned this well-formed service name as a replacement for badm_pub.";
	case 6507:
		return "BoKS Dir Server";
	case 6508:
		return "BoKS Dir Server";
	case 6509:
		return "MGCS-MFP Port";
	case 6510:
		return "MCER Port";
	case 6511:
		return "Reserved";
	case 6513:
		return "NETCONF over TLS";
	case 6514:
		return "Syslog over TLS";
	case 6515:
		return "Elipse RPC Protocol";
	case 6543:
		return "lds_distrib";
	case 6544:
		return "LDS Dump Service";
	case 6547:
		return "APC 6547";
	case 6548:
		return "APC 6548";
	case 6549:
		return "APC 6549";
	case 6550:
		return "fg-sysupdate";
	case 6551:
		return "Software Update Manager";
	case 6556:
		return "Checkmk Monitoring Agent";
	case 6558:
		return "";
	case 6566:
		return "SANE Control Port";
	case 6568:
		return "CanIt Storage Manager IANA assigned this well-formed service name as a replacement for canit_store.";
	case 6579:
		return "Affiliate";
	case 6580:
		return "Parsec Masterserver";
	case 6581:
		return "Parsec Peer-to-Peer";
	case 6582:
		return "Parsec Gameserver";
	case 6583:
		return "JOA Jewel Suite";
	case 6600:
		return "Microsoft Hyper-V Live Migration";
	case 6601:
		return "Microsoft Threat Management Gateway SSTP";
	case 6602:
		return "Windows WSS Communication Framework";
	case 6619:
		return "ODETTE-FTP over TLS/SSL";
	case 6620:
		return "Kerberos V5 FTP Data";
	case 6621:
		return "Kerberos V5 FTP Control";
	case 6622:
		return "Multicast FTP";
	case 6623:
		return "Kerberos V5 Telnet";
	case 6624:
		return "DataScaler database";
	case 6625:
		return "DataScaler control";
	case 6626:
		return "WAGO Service and Update";
	case 6627:
		return "Allied Electronics NeXGen";
	case 6628:
		return "AFE Stock Channel M/C";
	case 6629:
		return "Secondary";
	case 6632:
		return "eGenix mxODBC Connect";
	case 6633:
		return "Reserved";
	case 6634:
		return "Reserved";
	case 6635:
		return "Reserved";
	case 6636:
		return "Reserved";
	case 6640:
		return "Open vSwitch Database protocol";
	case 6653:
		return "OpenFlow";
	case 6655:
		return "PC SOFT - Software factory UI/manager";
	case 6656:
		return "Emergency Message Control Service";
	case 6657:
		return "Reserved";
	case 6670:
		return "Vocaltec Global Online Directory";
	case 6671:
		return "P4P Portal Service";
	case 6672:
		return "vision_server IANA assigned this well-formed service name as a replacement for vision_server.";
	case 6673:
		return "vision_elmd IANA assigned this well-formed service name as a replacement for vision_elmd.";
	case 6678:
		return "Viscount Freedom Bridge Protocol";
	case 6679:
		return "Osorno Automation";
	case 6687:
		return "CleverView for cTrace Message Service";
	case 6688:
		return "CleverView for TCP/IP Message Service";
	case 6689:
		return "Tofino Security Appliance";
	case 6690:
		return "CLEVERDetect Message Service";
	case 6696:
		return "Reserved";
	case 6697:
		return "Internet Relay Chat via TLS/SSL";
	case 6699:
		return "Reserved";
	case 6701:
		return "KTI/ICAD Nameserver";
	case 6702:
		return "e-Design network";
	case 6703:
		return "e-Design web";
	case 6704:
		return "Reserved";
	case 6705:
		return "Reserved";
	case 6706:
		return "Reserved";
	case 6714:
		return "Internet Backplane Protocol";
	case 6715:
		return "Fibotrader Communications";
	case 6716:
		return "Princity Agent";
	case 6767:
		return "BMC PERFORM AGENT";
	case 6768:
		return "BMC PERFORM MGRD";
	case 6769:
		return "ADInstruments GxP Server";
	case 6770:
		return "PolyServe http";
	case 6771:
		return "PolyServe https";
	case 6777:
		return "netTsunami Tracker";
	case 6778:
		return "netTsunami p2p storage system";
	case 6784:
		return "Reserved";
	case 6785:
		return "DGPF Individual Exchange";
	case 6786:
		return "Sun Java Web Console JMX";
	case 6787:
		return "Sun Web Console Admin";
	case 6788:
		return "SMC-HTTP";
	case 6789:
		return "GSS-API for the Oracle Remote Administration Daemon";
	case 6790:
		return "HNMP";
	case 6791:
		return "Halcyon Network Manager";
	case 6801:
		return "ACNET Control System Protocol";
	case 6817:
		return "PenTBox Secure IM Protocol";
	case 6831:
		return "ambit-lm";
	case 6841:
		return "Netmo Default";
	case 6842:
		return "Netmo HTTP";
	case 6850:
		return "ICCRUSHMORE";
	case 6868:
		return "Acctopus Command Channel";
	case 6888:
		return "MUSE";
	case 6900:
		return "R*TIME Viewer Data Interface";
	case 6901:
		return "Novell Jetstream messaging protocol";
	case 6924:
		return "Ping with RX/TX latency/loss split";
	case 6935:
		return "EthoScan Service";
	case 6936:
		return "XenSource Management Service";
	case 6946:
		return "Biometrics Server";
	case 6951:
		return "OTLP";
	case 6961:
		return "JMACT3";
	case 6962:
		return "jmevt2";
	case 6963:
		return "swismgr1";
	case 6964:
		return "swismgr2";
	case 6965:
		return "swistrap";
	case 6966:
		return "swispol";
	case 6969:
		return "acmsoda";
	case 6970:
		return "Conductor test coordination protocol";
	case 6980:
		return "Reserved";
	case 6997:
		return "Mobility XE Protocol";
	case 6998:
		return "IATP-highPri";
	case 6999:
		return "IATP-normalPri";
	case 7000:
		return "file server itself";
	case 7001:
		return "callbacks to cache managers";
	case 7002:
		return "users & groups database";
	case 7003:
		return "volume location database";
	case 7004:
		return "AFS/Kerberos authentication service";
	case 7005:
		return "volume managment server";
	case 7006:
		return "error interpretation service";
	case 7007:
		return "basic overseer process";
	case 7008:
		return "server-to-server updater";
	case 7009:
		return "remote cache manager service";
	case 7010:
		return "onlinet uninterruptable power supplies";
	case 7011:
		return "Talon Discovery Port";
	case 7012:
		return "Talon Engine";
	case 7013:
		return "Microtalon Discovery";
	case 7014:
		return "Microtalon Communications";
	case 7015:
		return "Talon Webserver";
	case 7016:
		return "SPG Controls Carrier";
	case 7017:
		return "GeneRic Autonomic Signaling Protocol";
	case 7018:
		return "FISA Service";
	case 7019:
		return "doceri drawing service control";
	case 7020:
		return "DP Serve";
	case 7021:
		return "DP Serve Admin";
	case 7022:
		return "CT Discovery Protocol";
	case 7023:
		return "Comtech T2 NMCS";
	case 7024:
		return "Vormetric service";
	case 7025:
		return "Vormetric Service II";
	case 7026:
		return "Loreji Webhosting Panel";
	case 7030:
		return "ObjectPlanet probe";
	case 7031:
		return "IPOSPLANET retailing multi devices protocol";
	case 7040:
		return "Reserved";
	case 7070:
		return "ARCP";
	case 7071:
		return "IWGADTS Aircraft Housekeeping Message";
	case 7072:
		return "iba Device Configuration Protocol";
	case 7073:
		return "MarTalk protocol";
	case 7080:
		return "EmpowerID Communication";
	case 7088:
		return "Reserved";
	case 7095:
		return "Reserved";
	case 7099:
		return "lazy-ptop";
	case 7100:
		return "X Font Service";
	case 7101:
		return "Embedded Light Control Network";
	case 7107:
		return "Reserved";
	case 7117:
		return "Encrypted chat and file transfer service";
	case 7121:
		return "Virtual Prototypes License Manager";
	case 7123:
		return "End-to-end TLS Relay Control Connection";
	case 7128:
		return "intelligent data manager";
	case 7129:
		return "Catalog Content Search";
	case 7161:
		return "CA BSM Comm";
	case 7162:
		return "CA Storage Manager";
	case 7163:
		return "CA Connection Broker";
	case 7164:
		return "File System Repository Agent";
	case 7165:
		return "Document WCF Server";
	case 7166:
		return "Aruba eDiscovery Server";
	case 7167:
		return "CA SRM Agent";
	case 7168:
		return "cncKadServer DB & Inventory Services";
	case 7169:
		return "Consequor Consulting Process Integration Bridge";
	case 7170:
		return "Adaptive Name/Service Resolution";
	case 7171:
		return "Discovery and Retention Mgt Production";
	case 7172:
		return "Port used for MetalBend programmable interface";
	case 7173:
		return "zSecure Server";
	case 7174:
		return "Clutild";
	case 7181:
		return "Reserved";
	case 7200:
		return "FODMS FLIP";
	case 7201:
		return "DLIP";
	case 7202:
		return "Inter-Channel Termination Protocol (ICTP) for multi-wavelength PON";
	case 7215:
		return "Communication ports for PaperStream Server services";
	case 7216:
		return "PaperStream Capture Professional";
	case 7227:
		return "Registry A & M Protocol";
	case 7228:
		return "Citrix Universal Printing Port";
	case 7229:
		return "Citrix UPP Gateway";
	case 7234:
		return "Traffic forwarding for Okta cloud infra";
	case 7235:
		return "Reserved";
	case 7236:
		return "Wi-Fi Alliance Wi-Fi Display Protocol";
	case 7237:
		return "PADS (Public Area Display System) Server";
	case 7244:
		return "FrontRow Calypso Human Interface Control Protocol";
	case 7262:
		return "Calypso Network Access Protocol";
	case 7272:
		return "WatchMe Monitoring 7272";
	case 7273:
		return "OMA Roaming Location";
	case 7274:
		return "OMA Roaming Location SEC";
	case 7275:
		return "OMA UserPlane Location";
	case 7276:
		return "OMA Internal Location Protocol";
	case 7277:
		return "OMA Internal Location Secure Protocol";
	case 7278:
		return "OMA Dynamic Content Delivery over CBS";
	case 7279:
		return "Citrix Licensing";
	case 7280:
		return "ITACTIONSERVER 1";
	case 7281:
		return "ITACTIONSERVER 2";
	case 7282:
		return "eventACTION/ussACTION (MZCA) server";
	case 7283:
		return "General Statistics Rendezvous Protocol";
	case 7365:
		return "LifeKeeper Communications";
	case 7391:
		return "mind-file system server";
	case 7392:
		return "mrss-rendezvous server";
	case 7393:
		return "nFoldMan Remote Publish";
	case 7394:
		return "File system export of backup images";
	case 7395:
		return "winqedit";
	case 7397:
		return "Hexarc Command Language";
	case 7400:
		return "RTPS Discovery";
	case 7401:
		return "RTPS Data-Distribution User-Traffic";
	case 7402:
		return "RTPS Data-Distribution Meta-Traffic";
	case 7410:
		return "Ionix Network Monitor";
	case 7411:
		return "Streaming of measurement data";
	case 7420:
		return "Reserved";
	case 7421:
		return "Matisse Port Monitor";
	case 7426:
		return "OpenView DM Postmaster Manager";
	case 7427:
		return "OpenView DM Event Agent Manager";
	case 7428:
		return "OpenView DM Log Agent Manager";
	case 7429:
		return "OpenView DM rqt communication";
	case 7430:
		return "OpenView DM xmpv7 api pipe";
	case 7431:
		return "OpenView DM ovc/xmpv3 api pipe";
	case 7437:
		return "Faximum";
	case 7443:
		return "Oracle Application Server HTTPS";
	case 7471:
		return "Stateless Transport Tunneling Protocol";
	case 7473:
		return "Rise: The Vieneo Province";
	case 7474:
		return "Neo4j Graph Database";
	case 7478:
		return "IT Asset Management";
	case 7491:
		return "telops-lmd";
	case 7500:
		return "Silhouette User";
	case 7501:
		return "HP OpenView Bus Daemon";
	case 7508:
		return "Automation Device Configuration Protocol";
	case 7509:
		return "ACPLT - process automation service";
	case 7510:
		return "HP OpenView Application Server";
	case 7511:
		return "pafec-lm";
	case 7542:
		return "Saratoga Transfer Protocol";
	case 7543:
		return "atul server";
	case 7544:
		return "FlowAnalyzer DisplayServer";
	case 7545:
		return "FlowAnalyzer UtilityServer";
	case 7546:
		return "Cisco Fabric service";
	case 7547:
		return "Broadband Forum CWMP";
	case 7548:
		return "Threat Information Distribution Protocol";
	case 7549:
		return "Network Layer Signaling Transport Layer";
	case 7550:
		return "Reserved";
	case 7551:
		return "ControlONE Console signaling";
	case 7560:
		return "Sniffer Command Protocol";
	case 7563:
		return "Control Framework";
	case 7566:
		return "VSI Omega";
	case 7569:
		return "Dell EqualLogic Host Group Management";
	case 7570:
		return "Aries Kfinder";
	case 7574:
		return "Oracle Coherence Cluster Service";
	case 7588:
		return "Sun License Manager";
	case 7606:
		return "MIPI Alliance Debug";
	case 7624:
		return "Instrument Neutral Distributed Interface";
	case 7626:
		return "SImple Middlebox COnfiguration (SIMCO) Server";
	case 7627:
		return "SOAP Service Port";
	case 7628:
		return "Primary Agent Work Notification";
	case 7629:
		return "OpenXDAS Wire Protocol";
	case 7630:
		return "HA Web Konsole";
	case 7631:
		return "TESLA System Messaging";
	case 7633:
		return "PMDF Management";
	case 7648:
		return "bonjour-cuseeme";
	case 7663:
		return "Proprietary immutable distributed data storage";
	case 7672:
		return "iMQ STOMP Server";
	case 7673:
		return "iMQ STOMP Server over SSL";
	case 7674:
		return "iMQ SSL tunnel";
	case 7675:
		return "iMQ Tunnel";
	case 7676:
		return "iMQ Broker Rendezvous";
	case 7677:
		return "Sun App Server - HTTPS";
	case 7680:
		return "Microsoft Delivery Optimization Peer-to-Peer";
	case 7683:
		return "Cleondris DMT";
	case 7687:
		return "Bolt database connection";
	case 7689:
		return "Collaber Network Service";
	case 7690:
		return "Service-Oriented Vehicle Diagnostics";
	case 7697:
		return "KLIO communications";
	case 7700:
		return "EM7 Secure Communications";
	case 7701:
		return "Reserved";
	case 7707:
		return "EM7 Dynamic Updates";
	case 7708:
		return "scientia.net";
	case 7720:
		return "MedImage Portal";
	case 7724:
		return "Novell Snap-in Deep Freeze Control";
	case 7725:
		return "Nitrogen Service";
	case 7726:
		return "FreezeX Console Service";
	case 7727:
		return "Trident Systems Data";
	case 7728:
		return "Open-Source Virtual Reality";
	case 7734:
		return "Smith Protocol over IP";
	case 7738:
		return "HP Enterprise Discovery Agent";
	case 7741:
		return "ScriptView Network";
	case 7742:
		return "Mugginsoft Script Server Service";
	case 7743:
		return "Sakura Script Transfer Protocol";
	case 7744:
		return "RAQMON PDU";
	case 7747:
		return "Put/Run/Get Protocol";
	case 7775:
		return "A File System using TLS over a wide area network";
	case 7777:
		return "cbt";
	case 7778:
		return "Interwise";
	case 7779:
		return "VSTAT";
	case 7781:
		return "accu-lmgr";
	case 7784:
		return "Reserved";
	case 7786:
		return "MINIVEND";
	case 7787:
		return "Popup Reminders Receive";
	case 7789:
		return "Office Tools Pro Receive";
	case 7794:
		return "Q3ADE Cluster Service";
	case 7797:
		return "Propel Connector port";
	case 7798:
		return "Propel Encoder port";
	case 7799:
		return "Alternate BSDP Service";
	case 7800:
		return "Apple Software Restore";
	case 7801:
		return "Secure Server Protocol - client";
	case 7802:
		return "Reserved";
	case 7810:
		return "Riverbed WAN Optimization Protocol";
	case 7845:
		return "APC 7845";
	case 7846:
		return "APC 7846";
	case 7847:
		return "A product key authentication protocol made by CSO";
	case 7869:
		return "MobileAnalyzer& MobileMonitor";
	case 7870:
		return "Riverbed Steelhead Mobile Service";
	case 7871:
		return "Mobile Device Management";
	case 7872:
		return "Reserved";
	case 7878:
		return "Opswise Message Service";
	case 7880:
		return "Pearson";
	case 7887:
		return "Universal Broker";
	case 7900:
		return "Multicast Event";
	case 7901:
		return "TNOS Service Protocol";
	case 7902:
		return "TNOS shell Protocol";
	case 7903:
		return "TNOS Secure DiaguardProtocol";
	case 7913:
		return "QuickObjects secure port";
	case 7932:
		return "Tier 2 Data Resource Manager";
	case 7933:
		return "Tier 2 Business Rules Manager";
	case 7962:
		return "Encrypted";
	case 7967:
		return "Supercell";
	case 7979:
		return "Micromuse-ncps";
	case 7980:
		return "Quest Vista";
	case 7981:
		return "Spotlight on SQL Server Desktop Collect";
	case 7982:
		return "Spotlight on SQL Server Desktop Agent";
	case 7997:
		return "PUSH Notification Service";
	case 7998:
		return "Reserved";
	case 7999:
		return "iRDMI2";
	case 8000:
		return "iRDMI";
	case 8001:
		return "VCOM Tunnel";
	case 8002:
		return "Teradata ORDBMS";
	case 8003:
		return "Mulberry Connect Reporting Service";
	case 8004:
		return "Opensource Evolv Enterprise Platform P2P Network Node Connection Protocol";
	case 8005:
		return "MXI Generation II for z/OS";
	case 8006:
		return "World Programming analytics";
	case 8007:
		return "I/O oriented cluster computing software";
	case 8008:
		return "HTTP Alternate";
	case 8009:
		return "NVMe over Fabrics Discovery Service";
	case 8015:
		return "Configuration Cloud Service";
	case 8016:
		return "Beckhoff Automation Device Specification";
	case 8017:
		return "Reserved";
	case 8019:
		return "QB DB Dynamic Port";
	case 8020:
		return "Intuit Entitlement Service and Discovery";
	case 8021:
		return "Intuit Entitlement Client";
	case 8022:
		return "oa-system";
	case 8023:
		return "ARCATrust vault API";
	case 8025:
		return "CA Audit Distribution Agent";
	case 8026:
		return "CA Audit Distribution Server";
	case 8027:
		return "peer tracker and data relay service";
	case 8032:
		return "ProEd";
	case 8033:
		return "MindPrint";
	case 8034:
		return ".vantronix Management";
	case 8040:
		return "Ampify Messaging Protocol";
	case 8041:
		return "Xcorpeon ASIC Carrier Ethernet Transport";
	case 8042:
		return "FireScope Agent";
	case 8043:
		return "FireScope Server";
	case 8044:
		return "FireScope Management Interface";
	case 8051:
		return "Rocrail Client Service";
	case 8052:
		return "Senomix Timesheets Server";
	case 8053:
		return "Senomix Timesheets Client [1 year assignment]";
	case 8054:
		return "Senomix Timesheets Server [1 year assignment]";
	case 8055:
		return "Senomix Timesheets Server [1 year assignment]";
	case 8056:
		return "Senomix Timesheets Server [1 year assignment]";
	case 8057:
		return "Senomix Timesheets Client [1 year assignment]";
	case 8058:
		return "Senomix Timesheets Client [1 year assignment]";
	case 8059:
		return "Senomix Timesheets Client [1 year assignment]";
	case 8060:
		return "Reserved";
	case 8061:
		return "Nikatron Device Protocol";
	case 8066:
		return "Toad BI Application Server";
	case 8067:
		return "Infinidat async replication";
	case 8070:
		return "Oracle Unified Communication Suite's Indexed Search Converter";
	case 8074:
		return "Gadu-Gadu";
	case 8077:
		return "Mles is a client-server data distribution protocol targeted to serve as a lightweight and reliable distributed publish/subscribe database service.";
	case 8080:
		return "HTTP Alternate (see port 80)";
	case 8081:
		return "Sun Proxy Admin Service";
	case 8082:
		return "Utilistor (Client)";
	case 8083:
		return "Utilistor (Server)";
	case 8084:
		return "Snarl Network Protocol over HTTP";
	case 8086:
		return "Distributed SCADA Networking Rendezvous Port";
	case 8087:
		return "Simplify Media SPP Protocol";
	case 8088:
		return "Radan HTTP";
	case 8090:
		return "Vehicle to station messaging";
	case 8091:
		return "Jam Link Framework";
	case 8097:
		return "SAC Port Id";
	case 8100:
		return "Xprint Server";
	case 8101:
		return "Logical Domains Migration";
	case 8102:
		return "Oracle Kernel zones migration server";
	case 8111:
		return "Reserved";
	case 8115:
		return "MTL8000 Matrix";
	case 8116:
		return "Check Point Clustering";
	case 8117:
		return "Purity replication clustering and remote management";
	case 8118:
		return "Privoxy HTTP proxy";
	case 8121:
		return "Apollo Data Port";
	case 8122:
		return "Apollo Admin Port";
	case 8128:
		return "PayCash Online Protocol";
	case 8129:
		return "PayCash Wallet-Browser";
	case 8130:
		return "INDIGO-VRMI";
	case 8131:
		return "INDIGO-VBCP";
	case 8132:
		return "dbabble";
	case 8140:
		return "The Puppet master service";
	case 8148:
		return "i-SDD file transfer";
	case 8149:
		return "Reserved";
	case 8153:
		return "QuantaStor Management Interface";
	case 8160:
		return "Patrol";
	case 8161:
		return "Patrol SNMP";
	case 8162:
		return "LPAR2RRD client server communication";
	case 8181:
		return "Intermapper network management system";
	case 8182:
		return "VMware Fault Domain Manager";
	case 8183:
		return "ProRemote";
	case 8184:
		return "Remote iTach Connection";
	case 8190:
		return "Generic control plane for RPHY";
	case 8191:
		return "Limner Pressure";
	case 8192:
		return "SpyTech Phone Service";
	case 8194:
		return "Bloomberg data API";
	case 8195:
		return "Bloomberg feed";
	case 8199:
		return "VVR DATA";
	case 8200:
		return "TRIVNET";
	case 8201:
		return "TRIVNET";
	case 8202:
		return "Reserved";
	case 8204:
		return "LM Perfworks";
	case 8205:
		return "LM Instmgr";
	case 8206:
		return "LM Dta";
	case 8207:
		return "LM SServer";
	case 8208:
		return "LM Webwatcher";
	case 8211:
		return "Reserved";
	case 8230:
		return "RexecJ Server";
	case 8231:
		return "Reserved";
	case 8232:
		return "Reserved";
	case 8243:
		return "Synapse Non Blocking HTTPS";
	case 8266:
		return "Reserved";
	case 8270:
		return "Robot Framework Remote Library Interface";
	case 8276:
		return "Microsoft Connected Cache";
	case 8280:
		return "Synapse Non Blocking HTTP";
	case 8282:
		return "Libelle EnterpriseBus";
	case 8292:
		return "Bloomberg professional";
	case 8293:
		return "Hiperscan Identification Service";
	case 8294:
		return "Bloomberg intelligent client";
	case 8300:
		return "Transport Management Interface";
	case 8301:
		return "Amberon PPC/PPS";
	case 8313:
		return "Hub Open Network";
	case 8320:
		return "Thin(ium) Network Protocol";
	case 8321:
		return "Thin(ium) Network Protocol";
	case 8322:
		return "Garmin Marine";
	case 8351:
		return "Server Find";
	case 8376:
		return "Cruise ENUM";
	case 8377:
		return "Cruise SWROUTE";
	case 8378:
		return "Cruise CONFIG";
	case 8379:
		return "Cruise DIAGS";
	case 8380:
		return "Cruise UPDATE";
	case 8383:
		return "M2m Services";
	case 8384:
		return "Reserved";
	case 8400:
		return "cvd";
	case 8401:
		return "sabarsd";
	case 8402:
		return "abarsd";
	case 8403:
		return "admind";
	case 8404:
		return "SuperVault Cloud";
	case 8405:
		return "SuperVault Backup";
	case 8415:
		return "Delphix Session Protocol";
	case 8416:
		return "eSpeech Session Protocol";
	case 8417:
		return "eSpeech RTP Protocol";
	case 8423:
		return "Aristech text-to-speech server";
	case 8432:
		return "PostgreSQL Backup";
	case 8433:
		return "Reserved";
	case 8442:
		return "CyBro A-bus Protocol";
	case 8443:
		return "PCsync HTTPS";
	case 8444:
		return "PCsync HTTP";
	case 8445:
		return "Port for copy peer sync feature";
	case 8448:
		return "Matrix Federation Protocol";
	case 8450:
		return "npmp";
	case 8457:
		return "Nexenta Management GUI";
	case 8470:
		return "Cisco Address Validation Protocol";
	case 8471:
		return "PIM over Reliable Transport";
	case 8472:
		return "Overlay Transport Virtualization (OTV)";
	case 8473:
		return "Virtual Point to Point";
	case 8474:
		return "AquaMinds NoteShare";
	case 8500:
		return "Flight Message Transfer Protocol";
	case 8501:
		return "CYTEL Message Transfer Management";
	case 8502:
		return "FTN Message Transfer Protocol";
	case 8503:
		return "Reserved";
	case 8554:
		return "RTSP Alternate (see port 554)";
	case 8555:
		return "SYMAX D-FENCE";
	case 8567:
		return "DOF Tunneling Protocol";
	case 8600:
		return "Surveillance Data";
	case 8609:
		return "Reserved";
	case 8610:
		return "Canon MFNP Service";
	case 8611:
		return "Canon BJNP Port 1";
	case 8612:
		return "Canon BJNP Port 2";
	case 8613:
		return "Canon BJNP Port 3";
	case 8614:
		return "Canon BJNP Port 4";
	case 8615:
		return "Imink Service Control";
	case 8665:
		return "Monetra";
	case 8666:
		return "Monetra Administrative Access";
	case 8668:
		return "Spartan management";
	case 8675:
		return "Motorola Solutions Customer Programming Software for Radio Management";
	case 8686:
		return "Sun App Server - JMX/RMI";
	case 8688:
		return "OpenRemote Controller HTTP/REST";
	case 8699:
		return "VNYX Primary Port";
	case 8710:
		return "gRPC for SEMI Standards implementations";
	case 8711:
		return "Nuance Voice Control";
	case 8732:
		return "Reserved";
	case 8733:
		return "iBus";
	case 8750:
		return "DEY Storage Key Negotiation";
	case 8763:
		return "MC-APPSERVER";
	case 8764:
		return "OPENQUEUE";
	case 8765:
		return "Ultraseek HTTP";
	case 8766:
		return "Agilent Connectivity Service";
	case 8767:
		return "Online mobile multiplayer game";
	case 8768:
		return "Sandpolis Server";
	case 8769:
		return "Okta MultiPlatform Access Mgmt for Cloud Svcs";
	case 8770:
		return "Digital Photo Access Protocol (iPhoto)";
	case 8778:
		return "Stonebranch Universal Enterprise Controller";
	case 8786:
		return "Message Client";
	case 8787:
		return "Message Server";
	case 8793:
		return "Accedian Performance Measurement";
	case 8800:
		return "Sun Web Server Admin Service";
	case 8804:
		return "truecm";
	case 8805:
		return "Reserved";
	case 8807:
		return "Reserved";
	case 8808:
		return "Reserved";
	case 8809:
		return "Reserved";
	case 8873:
		return "dxspider linking protocol";
	case 8880:
		return "CDDBP";
	case 8881:
		return "Galaxy4D Online Game Engine";
	case 8883:
		return "Secure MQTT";
	case 8888:
		return "NewsEDGE server TCP (TCP 1)";
	case 8889:
		return "Desktop Data TCP 1";
	case 8890:
		return "Desktop Data TCP 2";
	case 8891:
		return "Desktop Data TCP 3: NESS application";
	case 8892:
		return "Desktop Data TCP 4: FARM product";
	case 8893:
		return "Desktop Data TCP 5: NewsEDGE/Web application";
	case 8894:
		return "Desktop Data TCP 6: COAL application";
	case 8899:
		return "ospf-lite";
	case 8900:
		return "JMB-CDS 1";
	case 8901:
		return "JMB-CDS 2";
	case 8908:
		return "WFA Device Provisioning Protocol";
	case 8910:
		return "manyone-http";
	case 8911:
		return "manyone-xml";
	case 8912:
		return "Windows Client Backup";
	case 8913:
		return "Dragonfly System Service";
	case 8937:
		return "Transaction Warehouse Data Service";
	case 8953:
		return "unbound dns nameserver control";
	case 8954:
		return "Cumulus Admin Port";
	case 8980:
		return "Network of Devices Provider";
	case 8981:
		return "Reserved";
	case 8989:
		return "Sun Web Server SSL Admin Service";
	case 8990:
		return "webmail HTTP service";
	case 8991:
		return "webmail HTTPS service";
	case 8997:
		return "Oracle Messaging Server Event Notification Service";
	case 8998:
		return "Canto RoboFlow Control";
	case 8999:
		return "Brodos Crypto Trade Protocol";
	case 9000:
		return "CSlistener";
	case 9001:
		return "ETL Service Manager";
	case 9002:
		return "DynamID authentication";
	case 9005:
		return "Golem Inter-System RPC";
	case 9007:
		return "Reserved";
	case 9008:
		return "Open Grid Services Server";
	case 9009:
		return "Pichat Server";
	case 9010:
		return "Secure Data Replicator Protocol";
	case 9011:
		return "Reserved";
	case 9020:
		return "TAMBORA";
	case 9021:
		return "Pangolin Identification";
	case 9022:
		return "PrivateArk Remote Agent";
	case 9023:
		return "Secure Web Access - 1";
	case 9024:
		return "Secure Web Access - 2";
	case 9025:
		return "Secure Web Access - 3";
	case 9026:
		return "Secure Web Access - 4";
	case 9050:
		return "Versiera Agent Listener";
	case 9051:
		return "Fusion-io Central Manager Service";
	case 9060:
		return "CardWeb request-response I/O exchange";
	case 9080:
		return "Groove GLRPC";
	case 9081:
		return "Reserved";
	case 9083:
		return "EMC PowerPath Mgmt Service";
	case 9084:
		return "IBM AURORA Performance Visualizer";
	case 9085:
		return "IBM Remote System Console";
	case 9086:
		return "Vesa Net2Display";
	case 9087:
		return "Classic Data Server";
	case 9088:
		return "IBM Informix SQL Interface";
	case 9089:
		return "IBM Informix SQL Interface - Encrypted";
	case 9090:
		return "WebSM";
	case 9091:
		return "xmltec-xmlmail";
	case 9092:
		return "Xml-Ipc Server Reg";
	case 9093:
		return "Copycat database replication service";
	case 9100:
		return "PDL Data Streaming Port";
	case 9101:
		return "Bacula Director";
	case 9102:
		return "Bacula File Daemon";
	case 9103:
		return "Bacula Storage Daemon";
	case 9104:
		return "PeerWire";
	case 9105:
		return "Xadmin Control Service";
	case 9106:
		return "Astergate Control Service";
	case 9107:
		return "AstergateFax Control Service";
	case 9111:
		return "Multiple Purpose";
	case 9119:
		return "MXit Instant Messaging";
	case 9122:
		return "Global Relay compliant mobile instant messaging protocol";
	case 9123:
		return "Global Relay compliant instant messaging protocol";
	case 9131:
		return "Dynamic Device Discovery";
	case 9160:
		return "apani1";
	case 9161:
		return "apani2";
	case 9162:
		return "apani3";
	case 9163:
		return "apani4";
	case 9164:
		return "apani5";
	case 9191:
		return "Sun AppSvr JPDA";
	case 9200:
		return "WAP connectionless session service";
	case 9201:
		return "WAP session service";
	case 9202:
		return "WAP secure connectionless session service";
	case 9203:
		return "WAP secure session service";
	case 9204:
		return "WAP vCard";
	case 9205:
		return "WAP vCal";
	case 9206:
		return "WAP vCard Secure";
	case 9207:
		return "WAP vCal Secure";
	case 9208:
		return "rjcdb vCard";
	case 9209:
		return "ALMobile System Service";
	case 9210:
		return "OMA Mobile Location Protocol";
	case 9211:
		return "OMA Mobile Location Protocol Secure";
	case 9212:
		return "Server View dbms access";
	case 9213:
		return "ServerStart RemoteControl";
	case 9214:
		return "IPDC ESG BootstrapService";
	case 9215:
		return "Integrated Setup and Install Service";
	case 9216:
		return "Aionex Communication Management Engine";
	case 9217:
		return "FSC Communication Port";
	case 9222:
		return "QSC Team Coherence";
	case 9255:
		return "Manager On Network";
	case 9277:
		return "Reserved";
	case 9278:
		return "Pegasus GPS Platform";
	case 9279:
		return "Pegaus GPS System Control Interface";
	case 9280:
		return "Predicted GPS";
	case 9281:
		return "SofaWare transport port 1";
	case 9282:
		return "SofaWare transport port 2";
	case 9283:
		return "CallWaveIAM";
	case 9284:
		return "VERITAS Information Serve";
	case 9285:
		return "N2H2 Filter Service Port";
	case 9286:
		return "Reserved";
	case 9287:
		return "Cumulus";
	case 9292:
		return "ArmTech Daemon";
	case 9293:
		return "StorView Client";
	case 9294:
		return "ARMCenter http Service";
	case 9295:
		return "ARMCenter https Service";
	case 9300:
		return "Virtual Racing Service";
	case 9306:
		return "Sphinx search server (MySQL listener)";
	case 9310:
		return "SAP Message Server";
	case 9312:
		return "Sphinx search server";
	case 9318:
		return "PKIX TimeStamp over TLS";
	case 9321:
		return "guibase";
	case 9339:
		return "gRPC Network Mgmt/Operations Interface";
	case 9340:
		return "gRPC Routing Information Base Interface";
	case 9343:
		return "MpIdcMgr";
	case 9344:
		return "Mphlpdmc";
	case 9345:
		return "Rancher Agent";
	case 9346:
		return "C Tech Licensing";
	case 9374:
		return "fjdmimgr";
	case 9380:
		return "Brivs! Open Extensible Protocol";
	case 9387:
		return "D2D Configuration Service";
	case 9388:
		return "D2D Data Transfer Service";
	case 9389:
		return "Active Directory Web Services";
	case 9390:
		return "OpenVAS Transfer Protocol";
	case 9396:
		return "fjinvmgr";
	case 9397:
		return "MpIdcAgt";
	case 9400:
		return "Samsung Twain for Network Server";
	case 9401:
		return "Samsung Twain for Network Client";
	case 9402:
		return "Samsung PC2FAX for Network Server";
	case 9418:
		return "git pack transfer service";
	case 9443:
		return "WSO2 Tungsten HTTPS";
	case 9444:
		return "WSO2 ESB Administration Console HTTPS";
	case 9445:
		return "MindArray Systems Console Agent";
	case 9450:
		return "Sentinel Keys Server";
	case 9500:
		return "ismserver";
	case 9522:
		return "Reserved";
	case 9535:
		return "Management Suite Remote Control";
	case 9536:
		return "Surveillance buffering function";
	case 9555:
		return "Trispen Secure Remote Access";
	case 9559:
		return "P4Runtime gRPC Service";
	case 9592:
		return "LANDesk Gateway";
	case 9593:
		return "LANDesk Management Agent (cba8)";
	case 9594:
		return "Message System";
	case 9595:
		return "Ping Discovery Service";
	case 9596:
		return "Mercury Discovery";
	case 9597:
		return "PD Administration";
	case 9598:
		return "Very Simple Ctrl Protocol";
	case 9599:
		return "Robix";
	case 9600:
		return "MICROMUSE-NCPW";
	case 9612:
		return "StreamComm User Directory";
	case 9614:
		return "iADT Protocol over TLS";
	case 9616:
		return "eRunbook Agent IANA assigned this well-formed service name as a replacement for erunbook_agent.";
	case 9617:
		return "eRunbook Server IANA assigned this well-formed service name as a replacement for erunbook_server.";
	case 9618:
		return "Condor Collector Service";
	case 9628:
		return "ODBC Pathway Service";
	case 9629:
		return "UniPort SSO Controller";
	case 9630:
		return "Peovica Controller";
	case 9631:
		return "Peovica Collector";
	case 9632:
		return "Reserved";
	case 9640:
		return "ProQueSys Flows Service";
	case 9666:
		return "Zoom Control Panel Game Server Management";
	case 9667:
		return "Cross-platform Music Multiplexing System";
	case 9668:
		return "tec5 Spectral Device Control Protocol";
	case 9694:
		return "T-Mobile Client Wakeup Message";
	case 9695:
		return "Content Centric Networking";
	case 9700:
		return "Board M.I.T. Service";
	case 9747:
		return "L5NAS Parallel Channel";
	case 9750:
		return "Board M.I.T. Synchronous Collaboration";
	case 9753:
		return "rasadv";
	case 9762:
		return "WSO2 Tungsten HTTP";
	case 9800:
		return "WebDav Source Port";
	case 9801:
		return "Sakura Script Transfer Protocol-2";
	case 9802:
		return "WebDAV Source TLS/SSL";
	case 9875:
		return "Session Announcement v1";
	case 9876:
		return "Session Director";
	case 9877:
		return "The X.510 wrapper protocol";
	case 9878:
		return "Reserved";
	case 9888:
		return "CYBORG Systems";
	case 9889:
		return "Port for Cable network related data proxy or repeater";
	case 9898:
		return "MonkeyCom";
	case 9899:
		return "Reserved";
	case 9900:
		return "IUA";
	case 9903:
		return "Reserved";
	case 9909:
		return "domaintime";
	case 9911:
		return "SYPECom Transport Protocol";
	case 9925:
		return "XYBRID Cloud";
	case 9950:
		return "APC 9950";
	case 9951:
		return "APC 9951";
	case 9952:
		return "APC 9952";
	case 9953:
		return "9953";
	case 9954:
		return "HaloteC Instrument Network Protocol";
	case 9955:
		return "Contact Port for AllJoyn standard messaging";
	case 9956:
		return "Reserved";
	case 9966:
		return "OKI Data Network Setting Protocol";
	case 9978:
		return "XYBRID RT Server";
	case 9979:
		return "Valley Information Systems Weather station data";
	case 9981:
		return "Event sourcing database engine with a built-in programming language";
	case 9987:
		return "DSM/SCM Target Interface";
	case 9988:
		return "Software Essentials Secure HTTP server";
	case 9990:
		return "OSM Applet Server";
	case 9991:
		return "OSM Event Server";
	case 9992:
		return "OnLive-1";
	case 9993:
		return "OnLive-2";
	case 9994:
		return "OnLive-3";
	case 9995:
		return "Palace-4";
	case 9996:
		return "Palace-5";
	case 9997:
		return "Palace-6";
	case 9998:
		return "Distinct32";
	case 9999:
		return "distinct";
	case 10000:
		return "Network Data Management Protocol";
	case 10001:
		return "SCP Configuration";
	case 10002:
		return "EMC-Documentum Content Server Product";
	case 10003:
		return "EMC-Documentum Content Server Product IANA assigned this well-formed service name as a replacement for documentum_s.";
	case 10004:
		return "EMC Replication Manager Client";
	case 10005:
		return "EMC Replication Manager Server";
	case 10006:
		return "Sync replication protocol among different NetApp platforms";
	case 10007:
		return "MVS Capacity";
	case 10008:
		return "Octopus Multiplexer";
	case 10009:
		return "Systemwalker Desktop Patrol";
	case 10010:
		return "ooRexx rxapi services";
	case 10020:
		return "Hardware configuration and maintenance";
	case 10023:
		return "Reserved";
	case 10050:
		return "Zabbix Agent";
	case 10051:
		return "Zabbix Trapper";
	case 10055:
		return "Quantapoint FLEXlm Licensing Service";
	case 10080:
		return "Amanda";
	case 10081:
		return "FAM Archive Server";
	case 10100:
		return "VERITAS ITAP DDTP";
	case 10101:
		return "eZmeeting";
	case 10102:
		return "eZproxy";
	case 10103:
		return "eZrelay";
	case 10104:
		return "Systemwalker Desktop Patrol";
	case 10107:
		return "VERITAS BCTP";
	case 10110:
		return "NMEA-0183 Navigational Data";
	case 10111:
		return "Reserved";
	case 10113:
		return "NetIQ Endpoint";
	case 10114:
		return "NetIQ Qcheck";
	case 10115:
		return "NetIQ Endpoint";
	case 10116:
		return "NetIQ VoIP Assessor";
	case 10117:
		return "NetIQ IQCResource Managament Svc";
	case 10125:
		return "HotLink CIMple REST API";
	case 10128:
		return "BMC-PERFORM-SERVICE DAEMON";
	case 10129:
		return "BMC General Manager Server";
	case 10160:
		return "QB Database Server";
	case 10161:
		return "SNMP-TLS";
	case 10162:
		return "SNMP-Trap-TLS";
	case 10200:
		return "Trigence AE Soap Service";
	case 10201:
		return "Remote Server Management Service";
	case 10252:
		return "Apollo Relay Port";
	case 10253:
		return "Reserved";
	case 10260:
		return "Axis WIMP Port";
	case 10261:
		return "Tile remote machine learning";
	case 10288:
		return "Blocks";
	case 10321:
		return "Computer Op System Information Report";
	case 10439:
		return "Reserved";
	case 10443:
		return "CirrosSP Workstation Communication";
	case 10500:
		return "Reserved";
	case 10540:
		return "MOS Media Object Metadata Port";
	case 10541:
		return "MOS Running Order Port";
	case 10542:
		return "MOS Low Priority Port";
	case 10543:
		return "MOS SOAP Default Port";
	case 10544:
		return "MOS SOAP Optional Port";
	case 10548:
		return "Apple Document Sharing Service";
	case 10631:
		return "Printopia Serve";
	case 10800:
		return "Gestor de Acaparamiento para Pocket PCs";
	case 10805:
		return "LUCIA Pareja Data Group";
	case 10809:
		return "Linux Network Block Device";
	case 10810:
		return "Reserved";
	case 10860:
		return "Helix Client/Server";
	case 10880:
		return "BVEssentials HTTP API";
	case 10933:
		return "Listen port used by the Octopus Deploy Tentacle deployment agent";
	case 10990:
		return "Auxiliary RMI Port";
	case 11000:
		return "IRISA";
	case 11001:
		return "Metasys";
	case 11095:
		return "Nest device-to-device and device-to-service application protocol";
	case 11103:
		return "OrigoDB Server Sync Interface";
	case 11104:
		return "NetApp Intercluster Management";
	case 11105:
		return "NetApp Intercluster Data";
	case 11106:
		return "SGI LK Licensing service";
	case 11108:
		return "Reserved";
	case 11109:
		return "Data migration facility Manager (DMF) is a browser based interface to DMF";
	case 11110:
		return "Data migration facility (DMF) SOAP is a web server protocol to support remote access to DMF";
	case 11111:
		return "Viral Computing Environment (VCE)";
	case 11112:
		return "DICOM";
	case 11161:
		return "sun cacao snmp access point";
	case 11162:
		return "sun cacao JMX-remoting access point";
	case 11163:
		return "sun cacao rmi registry access point";
	case 11164:
		return "sun cacao command-streaming access point";
	case 11165:
		return "sun cacao web service access point";
	case 11171:
		return "Reserved";
	case 11172:
		return "OEM cacao JMX-remoting access point";
	case 11173:
		return "Straton Runtime Programing";
	case 11174:
		return "OEM cacao rmi registry access point";
	case 11175:
		return "OEM cacao web service access point";
	case 11201:
		return "smsqp";
	case 11202:
		return "DCSL Network Backup Services";
	case 11208:
		return "WiFree Service";
	case 11211:
		return "Memory cache service";
	case 11235:
		return "numerical systems messaging";
	case 11319:
		return "IMIP";
	case 11320:
		return "IMIP Channels Port";
	case 11321:
		return "Arena Server Listen";
	case 11367:
		return "ATM UHAS";
	case 11371:
		return "OpenPGP HTTP Keyserver";
	case 11430:
		return "Reserved";
	case 11489:
		return "ASG Cypress Secure Only";
	case 11600:
		return "Tempest Protocol Port";
	case 11623:
		return "EMC XtremSW distributed config";
	case 11720:
		return "H.323 Call Control Signalling Alternate";
	case 11723:
		return "EMC XtremSW distributed cache";
	case 11751:
		return "Intrepid SSL";
	case 11796:
		return "LanSchool";
	case 11876:
		return "X2E Xoraya Multichannel protocol";
	case 11877:
		return "Reserved";
	case 11967:
		return "SysInfo Service Protocol";
	case 11971:
		return "TiBS Service";
	case 12000:
		return "IBM Enterprise Extender SNA XID Exchange";
	case 12001:
		return "IBM Enterprise Extender SNA COS Network Priority";
	case 12002:
		return "IBM Enterprise Extender SNA COS High Priority";
	case 12003:
		return "IBM Enterprise Extender SNA COS Medium Priority";
	case 12004:
		return "IBM Enterprise Extender SNA COS Low Priority";
	case 12005:
		return "DBISAM Database Server - Regular";
	case 12006:
		return "DBISAM Database Server - Admin";
	case 12007:
		return "Accuracer Database System Server";
	case 12008:
		return "Accuracer Database System Admin";
	case 12009:
		return "Reserved";
	case 12010:
		return "ElevateDB Server";
	case 12012:
		return "Vipera Messaging Service";
	case 12013:
		return "Vipera Messaging Service over SSL Communication";
	case 12109:
		return "RETS over SSL";
	case 12121:
		return "NuPaper Session Service";
	case 12168:
		return "CA Web Access Service";
	case 12172:
		return "HiveP";
	case 12300:
		return "LinoGrid Engine";
	case 12302:
		return "Remote Administration Daemon (RAD) is a system service that offers secure";
	case 12321:
		return "Warehouse Monitoring Syst SSS";
	case 12322:
		return "Warehouse Monitoring Syst";
	case 12345:
		return "Italk Chat System";
	case 12546:
		return "Carbonite Server Replication Control";
	case 12753:
		return "tsaf port";
	case 12865:
		return "control port for the netperf benchmark";
	case 13160:
		return "I-ZIPQD";
	case 13216:
		return "Black Crow Software application logging";
	case 13217:
		return "R&S Proxy Installation Assistant Service";
	case 13218:
		return "EMC Virtual CAS Service";
	case 13223:
		return "PowWow Client";
	case 13224:
		return "PowWow Server";
	case 13400:
		return "DoIP Data";
	case 13720:
		return "BPRD Protocol (VERITAS NetBackup)";
	case 13721:
		return "BPDBM Protocol (VERITAS NetBackup)";
	case 13722:
		return "BP Java MSVC Protocol";
	case 13724:
		return "Veritas Network Utility";
	case 13782:
		return "VERITAS NetBackup";
	case 13783:
		return "VOPIED Protocol";
	case 13785:
		return "NetBackup Database";
	case 13786:
		return "Veritas-nomdb";
	case 13818:
		return "DSMCC Config";
	case 13819:
		return "DSMCC Session Messages";
	case 13820:
		return "DSMCC Pass-Thru Messages";
	case 13821:
		return "DSMCC Download Protocol";
	case 13822:
		return "DSMCC Channel Change Protocol";
	case 13823:
		return "Blackmagic Design Streaming Server";
	case 13832:
		return "Certificate Management and Issuing";
	case 13894:
		return "Ultimate Control communication protocol";
	case 13929:
		return "D-TA SYSTEMS";
	case 13930:
		return "MedEvolve Port Requester";
	case 14000:
		return "SCOTTY High-Speed Filetransfer";
	case 14001:
		return "SUA";
	case 14002:
		return "Reserved";
	case 14033:
		return "sage Best! Config Server 1";
	case 14034:
		return "sage Best! Config Server 2";
	case 14141:
		return "VCS Application";
	case 14142:
		return "IceWall Cert Protocol";
	case 14143:
		return "IceWall Cert Protocol over TLS";
	case 14145:
		return "GCM Application";
	case 14149:
		return "Veritas Traffic Director";
	case 14150:
		return "Veritas Cluster Server Command Server";
	case 14154:
		return "Veritas Application Director";
	case 14250:
		return "Fencing Server";
	case 14414:
		return "CA eTrust Web Update Service";
	case 14500:
		return "xpra network protocol";
	case 14936:
		return "hde-lcesrvr-1";
	case 14937:
		return "hde-lcesrvr-2";
	case 15000:
		return "Hypack Data Aquisition";
	case 15002:
		return "Open Network Environment TLS";
	case 15118:
		return "Reserved";
	case 15345:
		return "XPilot Contact Port";
	case 15363:
		return "3Link Negotiation";
	case 15555:
		return "Cisco Stateful NAT";
	case 15660:
		return "Backup Express Restore Server";
	case 15740:
		return "Picture Transfer Protocol";
	case 15998:
		return "Reserved";
	case 15999:
		return "ProGrammar Enterprise";
	case 16000:
		return "Administration Server Access";
	case 16001:
		return "Administration Server Connector";
	case 16002:
		return "GoodSync Mediation Service";
	case 16003:
		return "Reserved";
	case 16020:
		return "Filemaker Java Web Publishing Core";
	case 16021:
		return "Filemaker Java Web Publishing Core Binary";
	case 16161:
		return "Solaris SEA Port";
	case 16162:
		return "Solaris Audit - secure remote audit log";
	case 16309:
		return "etb4j";
	case 16310:
		return "Policy Distribute";
	case 16311:
		return "Policy definition and update management";
	case 16360:
		return "Network Serial Extension Ports One";
	case 16361:
		return "Network Serial Extension Ports Two";
	case 16367:
		return "Network Serial Extension Ports Three";
	case 16368:
		return "Network Serial Extension Ports Four";
	case 16384:
		return "Connected Corp";
	case 16385:
		return "Reliable Datagram Sockets";
	case 16619:
		return "X509 Objects Management Service";
	case 16665:
		return "Reliable multipath data transport for high latencies";
	case 16666:
		return "Reserved";
	case 16789:
		return "This server provides callable services to mainframe External Security Managers from any TCP/IP platform";
	case 16900:
		return "Newbay Mobile Client Update Service";
	case 16950:
		return "Simple Generic Client Interface Protocol";
	case 16991:
		return "INTEL-RCI-MP";
	case 16992:
		return "Intel(R) AMT SOAP/HTTP";
	case 16993:
		return "Intel(R) AMT SOAP/HTTPS";
	case 16994:
		return "Intel(R) AMT Redirection/TCP";
	case 16995:
		return "Intel(R) AMT Redirection/TLS";
	case 17007:
		return "";
	case 17010:
		return "Plan 9 cpu port";
	case 17184:
		return "Vestas Data Layer Protocol";
	case 17185:
		return "Sounds Virtual";
	case 17219:
		return "Chipper";
	case 17220:
		return "IEEE 1722 Transport Protocol for Time Sensitive Applications";
	case 17221:
		return "IEEE 1722.1 AVB Discovery";
	case 17222:
		return "Reserved";
	case 17223:
		return "ISA100 GCI is a service utilizing a common interface between an ISA100 Wireless gateway and a client application";
	case 17224:
		return "Reserved";
	case 17225:
		return "Train Realtime Data Protocol (TRDP) Message Data";
	case 17234:
		return "Integrius Secure Tunnel Protocol";
	case 17235:
		return "SSH Tectia Manager";
	case 17500:
		return "Dropbox LanSync Protocol";
	case 17555:
		return "Ailith management of routers";
	case 17729:
		return "Eclipse Aviation";
	case 17754:
		return "Encap. ZigBee Packets";
	case 17755:
		return "ZigBee IP Transport Service";
	case 17756:
		return "ZigBee IP Transport Secure Service";
	case 17777:
		return "SolarWinds Orion";
	case 18000:
		return "Beckman Instruments";
	case 18104:
		return "RAD PDF Service";
	case 18136:
		return "z/OS Resource Access Control Facility";
	case 18181:
		return "OPSEC CVP";
	case 18182:
		return "OPSEC UFP";
	case 18183:
		return "OPSEC SAM";
	case 18184:
		return "OPSEC LEA";
	case 18185:
		return "OPSEC OMI";
	case 18186:
		return "Occupational Health SC";
	case 18187:
		return "OPSEC ELA";
	case 18241:
		return "Check Point RTM";
	case 18242:
		return "Checkpoint router monitoring";
	case 18243:
		return "Checkpoint router state backup";
	case 18262:
		return "GV NetConfig Service";
	case 18463:
		return "AC Cluster";
	case 18516:
		return "Reserved";
	case 18634:
		return "Reliable Datagram Service";
	case 18635:
		return "Reliable Datagram Service over IP";
	case 18668:
		return "Manufacturing Execution Systems Mesh Communication";
	case 18769:
		return "IQue Protocol";
	case 18881:
		return "Infotos";
	case 18888:
		return "APCNECMP";
	case 19000:
		return "iGrid Server";
	case 19007:
		return "Scintilla protocol for device services";
	case 19020:
		return "J-Link TCP/IP Protocol";
	case 19191:
		return "OPSEC UAA";
	case 19194:
		return "UserAuthority SecureAgent";
	case 19220:
		return "Client Connection Management and Data Exchange Service";
	case 19283:
		return "Key Server for SASSAFRAS";
	case 19315:
		return "Key Shadow for SASSAFRAS";
	case 19398:
		return "mtrgtrans";
	case 19410:
		return "hp-sco";
	case 19411:
		return "hp-sca";
	case 19412:
		return "HP-SESSMON";
	case 19539:
		return "FXUPTP";
	case 19540:
		return "SXUPTP";
	case 19541:
		return "JCP Client";
	case 19788:
		return "Reserved";
	case 19790:
		return "FairCom Database";
	case 19998:
		return "IEC 60870-5-104 process control - secure";
	case 19999:
		return "Distributed Network Protocol - Secure";
	case 20000:
		return "DNP";
	case 20001:
		return "MicroSAN";
	case 20002:
		return "Commtact HTTP";
	case 20003:
		return "Commtact HTTPS";
	case 20005:
		return "OpenWebNet protocol for electric network";
	case 20012:
		return "Reserved";
	case 20013:
		return "Samsung Interdevice Interaction";
	case 20014:
		return "OpenDeploy Listener";
	case 20034:
		return "NetBurner ID Port IANA assigned this well-formed service name as a replacement for nburn_id.";
	case 20046:
		return "TMOP HL7 Message Transfer Service";
	case 20048:
		return "NFS mount protocol";
	case 20049:
		return "Network File System (NFS) over RDMA";
	case 20057:
		return "AvesTerra Hypergraph Transfer Protocol (HGTP)";
	case 20167:
		return "TOLfab Data Change";
	case 20202:
		return "IPD Tunneling Port";
	case 20222:
		return "iPulse-ICS";
	case 20480:
		return "emWave Message Service";
	case 20670:
		return "Track";
	case 20810:
		return "CRTech NLM";
	case 20999:
		return "At Hand MMP";
	case 21000:
		return "IRTrans Control";
	case 21010:
		return "Notezilla.Lan Server";
	case 21212:
		return "Distributed artificial intelligence";
	case 21213:
		return "Cohesity backup agents";
	case 21221:
		return "Services for Air Server";
	case 21553:
		return "Raima RDM TFS";
	case 21554:
		return "MineScape Design File Server";
	case 21590:
		return "VoFR Gateway";
	case 21800:
		return "TVNC Pro Multiplexing";
	case 21801:
		return "Safe AutoLogon";
	case 21845:
		return "webphone";
	case 21846:
		return "NetSpeak Corp. Directory Services";
	case 21847:
		return "NetSpeak Corp. Connection Services";
	case 21848:
		return "NetSpeak Corp. Automatic Call Distribution";
	case 21849:
		return "NetSpeak Corp. Credit Processing System";
	case 22000:
		return "SNAPenetIO";
	case 22001:
		return "OptoControl";
	case 22002:
		return "Opto Host Port 2";
	case 22003:
		return "Opto Host Port 3";
	case 22004:
		return "Opto Host Port 4";
	case 22005:
		return "Opto Host Port 5";
	case 22125:
		return "dCache Access Protocol";
	case 22128:
		return "GSI dCache Access Protocol";
	case 22222:
		return "EasyEngine is CLI tool to manage WordPress Sites on Nginx server";
	case 22273:
		return "wnn6";
	case 22305:
		return "CompactIS Tunnel";
	case 22333:
		return "ShowCockpit Networking";
	case 22335:
		return "Initium Labs Security and Automation Control";
	case 22343:
		return "CompactIS Secure Tunnel";
	case 22347:
		return "WibuKey Standard WkLan";
	case 22350:
		return "CodeMeter Standard";
	case 22351:
		return "TPC/IP requests of copy protection software to a server";
	case 22537:
		return "CaldSoft Backup server file transfer";
	case 22555:
		return "Vocaltec Web Conference";
	case 22763:
		return "Talika Main Server";
	case 22800:
		return "Telerate Information Platform LAN";
	case 22951:
		return "Telerate Information Platform WAN";
	case 23000:
		return "Inova LightLink Server Type 1";
	case 23001:
		return "Inova LightLink Server Type 2";
	case 23002:
		return "Inova LightLink Server Type 3";
	case 23003:
		return "Inova LightLink Server Type 4";
	case 23004:
		return "Inova LightLink Server Type 5";
	case 23005:
		return "Inova LightLink Server Type 6";
	case 23053:
		return "Generic Notification Transport Protocol";
	case 23272:
		return "Reserved";
	case 23294:
		return "5AFE SDN Directory";
	case 23333:
		return "Emulex HBAnyware Remote Management";
	case 23400:
		return "Novar Data";
	case 23401:
		return "Novar Alarm";
	case 23402:
		return "Novar Global";
	case 23456:
		return "Aequus Service";
	case 23457:
		return "Aequus Service Mgmt";
	case 23546:
		return "AreaGuard Neo - WebServer";
	case 24000:
		return "med-ltp";
	case 24001:
		return "med-fsp-rx";
	case 24002:
		return "med-fsp-tx";
	case 24003:
		return "med-supp";
	case 24004:
		return "med-ovw";
	case 24005:
		return "med-ci";
	case 24006:
		return "med-net-svc";
	case 24242:
		return "fileSphere";
	case 24249:
		return "Vista 4GL";
	case 24321:
		return "Isolv Local Directory";
	case 24322:
		return "Reserved";
	case 24323:
		return "Verimag mobile class protocol over TCP";
	case 24386:
		return "Intel RCI IANA assigned this well-formed service name as a replacement for intel_rci.";
	case 24465:
		return "Tonido Domain Server";
	case 24554:
		return "BINKP";
	case 24577:
		return "bilobit Service";
	case 24666:
		return "Service used by SmarDTV to communicate between a CAM and a second screen application";
	case 24676:
		return "Canditv Message Service";
	case 24677:
		return "FlashFiler";
	case 24678:
		return "Turbopower Proactivate";
	case 24680:
		return "TCC User HTTP Service";
	case 24754:
		return "Citrix StorageLink Gateway";
	case 24850:
		return "Reserved";
	case 24922:
		return "Find Identification of Network Devices";
	case 25000:
		return "icl-twobase1";
	case 25001:
		return "icl-twobase2";
	case 25002:
		return "icl-twobase3";
	case 25003:
		return "icl-twobase4";
	case 25004:
		return "icl-twobase5";
	case 25005:
		return "icl-twobase6";
	case 25006:
		return "icl-twobase7";
	case 25007:
		return "icl-twobase8";
	case 25008:
		return "icl-twobase9";
	case 25009:
		return "icl-twobase10";
	case 25576:
		return "Sauter Dongle";
	case 25604:
		return "Identifier Tracing Protocol";
	case 25793:
		return "Vocaltec Address Server";
	case 25900:
		return "TASP Network Comm";
	case 25901:
		return "NIObserver";
	case 25902:
		return "NILinkAnalyst";
	case 25903:
		return "NIProbe";
	case 25954:
		return "Reserved";
	case 25955:
		return "Reserved";
	case 26000:
		return "quake";
	case 26133:
		return "Symbolic Computation Software Composability Protocol";
	case 26208:
		return "wnn6-ds";
	case 26257:
		return "CockroachDB";
	case 26260:
		return "eZproxy";
	case 26261:
		return "eZmeeting";
	case 26262:
		return "K3 Software-Server";
	case 26263:
		return "K3 Software-Client";
	case 26486:
		return "EXOline-TCP";
	case 26487:
		return "EXOconfig";
	case 26489:
		return "EXOnet";
	case 27010:
		return "A protocol for managing license services";
	case 27017:
		return "Mongo database system";
	case 27345:
		return "ImagePump";
	case 27442:
		return "Job controller service";
	case 27504:
		return "Kopek HTTP Head Port";
	case 27782:
		return "ARS VISTA Application";
	case 27876:
		return "Astrolink Protocol";
	case 27999:
		return "TW Authentication/Key Distribution and";
	case 28000:
		return "NX License Manager";
	case 28001:
		return "PQ Service";
	case 28010:
		return "Gruber cash registry protocol";
	case 28080:
		return "thor/server - ML engine";
	case 28119:
		return "Reserved";
	case 28200:
		return "VoxelStorm game server";
	case 28240:
		return "Siemens GSM";
	case 28589:
		return "Building operating system services wide area verified exchange";
	case 29000:
		return "Siemens Licensing Server";
	case 29118:
		return "Reserved";
	case 29167:
		return "ObTools Message Protocol";
	case 29168:
		return "Reserved";
	case 29999:
		return "data exchange protocol for IEC61850 in wind power plants";
	case 30000:
		return "Secure Network Data Management Protocol";
	case 30001:
		return "Pago Services 1";
	case 30002:
		return "Pago Services 2";
	case 30003:
		return "Amicon FPSU-IP Remote Administration";
	case 30004:
		return "Reserved";
	case 30100:
		return "Remote Window Protocol";
	case 30260:
		return "Kingdoms Online (CraigAvenue)";
	case 30400:
		return "GroundStar RealTime System";
	case 30832:
		return "Reserved";
	case 30999:
		return "OpenView Service Desk Client";
	case 31016:
		return "Kollective Agent Secure Distributed Delivery Protocol";
	case 31020:
		return "Autotrac ACP 245";
	case 31029:
		return "Reserved";
	case 31337:
		return "eldim is a secure file upload proxy";
	case 31400:
		return "PACE license server";
	case 31416:
		return "XQoS network monitor";
	case 31457:
		return "TetriNET Protocol";
	case 31620:
		return "lm mon";
	case 31685:
		return "DS Expert Monitor IANA assigned this well-formed service name as a replacement for dsx_monitor.";
	case 31765:
		return "GameSmith Port";
	case 31948:
		return "Embedded Device Configuration Protocol TX IANA assigned this well-formed service name as a replacement for iceedcp_tx.";
	case 31949:
		return "Embedded Device Configuration Protocol RX IANA assigned this well-formed service name as a replacement for iceedcp_rx.";
	case 32034:
		return "iRacing helper service";
	case 32249:
		return "T1 Distributed Processor";
	case 32400:
		return "Plex multimedia";
	case 32483:
		return "Access Point Manager Link";
	case 32635:
		return "SecureNotebook-CLNT";
	case 32636:
		return "DMExpress";
	case 32767:
		return "FileNet BPM WS-ReliableMessaging Client";
	case 32768:
		return "Filenet TMS";
	case 32769:
		return "Filenet RPC";
	case 32770:
		return "Filenet NCH";
	case 32771:
		return "FileNET RMI";
	case 32772:
		return "FileNET Process Analyzer";
	case 32773:
		return "FileNET Component Manager";
	case 32774:
		return "FileNET Rules Engine";
	case 32775:
		return "Performance Clearinghouse";
	case 32776:
		return "FileNET BPM IOR";
	case 32777:
		return "FileNet BPM CORBA";
	case 32801:
		return "Multiple Listing Service Network";
	case 32811:
		return "Real Estate Transport Protocol";
	case 32896:
		return "Attachmate ID Manager";
	case 33000:
		return "WatchGuard Endpoint Communications";
	case 33060:
		return "MySQL Database Extended Interface";
	case 33123:
		return "Aurora (Balaena Ltd)";
	case 33331:
		return "DiamondCentral Interface";
	case 33333:
		return "Digital Gaslight Service";
	case 33334:
		return "SpeedTrace TraceAgent";
	case 33434:
		return "traceroute use";
	case 33435:
		return "Reserved";
	case 33656:
		return "SNIP Slave";
	case 33890:
		return "Adept IP protocol";
	case 34249:
		return "TurboNote Relay Server Default Port";
	case 34378:
		return "P-Net on IP local";
	case 34379:
		return "P-Net on IP remote";
	case 34567:
		return "dhanalakshmi.org EDI Service";
	case 34962:
		return "PROFInet RT Unicast";
	case 34963:
		return "PROFInet RT Multicast";
	case 34964:
		return "PROFInet Context Manager";
	case 34980:
		return "EtherCAT Port";
	case 35000:
		return "HeathView";
	case 35001:
		return "ReadyTech Viewer";
	case 35002:
		return "ReadyTech Sound Server";
	case 35003:
		return "ReadyTech DeviceMapper Server";
	case 35004:
		return "ReadyTech ClassManager";
	case 35005:
		return "ReadyTech LabTracker";
	case 35006:
		return "ReadyTech Helper Service";
	case 35100:
		return "Axiomatic discovery protocol";
	case 35354:
		return "KIT Messenger";
	case 35355:
		return "Altova License Management";
	case 35356:
		return "Gutters Note Exchange";
	case 35357:
		return "OpenStack ID Service";
	case 36001:
		return "AllPeers Network";
	case 36411:
		return "Reserved";
	case 36412:
		return "Reserved";
	case 36422:
		return "Reserved";
	case 36462:
		return "Reserved";
	case 36524:
		return "Febooti Automation Workshop";
	case 36602:
		return "Observium statistics collection agent";
	case 36700:
		return "MapX communication";
	case 36865:
		return "KastenX Pipe";
	case 37472:
		return "Reserved";
	case 37475:
		return "science + computing's Venus Administration Port";
	case 37483:
		return "Google Drive Sync";
	case 37601:
		return "Epipole File Transfer Protocol";
	case 37654:
		return "Unisys ClearPath ePortal";
	case 38000:
		return "InfoVista Server Database";
	case 38001:
		return "InfoVista Server Insertion";
	case 38002:
		return "Cresco Controller";
	case 38201:
		return "Galaxy7 Data Tunnel";
	case 38202:
		return "Fairview Message Service";
	case 38203:
		return "AppGate Policy Server";
	case 38412:
		return "Reserved";
	case 38422:
		return "Reserved";
	case 38462:
		return "Reserved";
	case 38472:
		return "Reserved";
	case 38638:
		return "Premier SQL Middleware Server";
	case 38800:
		return "Sruth is a service for the distribution of routinely-";
	case 38865:
		return "Security approval process for use of the secRMM SafeCopy program";
	case 39063:
		return "Children's hearing test/Telemedicine";
	case 39681:
		return "TurboNote Default Port";
	case 40000:
		return "SafetyNET p";
	case 40023:
		return "Reserved";
	case 40404:
		return "Simplify Printing TX";
	case 40841:
		return "CSCP";
	case 40842:
		return "CSCCREDIR";
	case 40843:
		return "CSCCFIREWALL";
	case 40853:
		return "Reserved";
	case 41111:
		return "Foursticks QoS Protocol";
	case 41121:
		return "Tentacle Server";
	case 41230:
		return "Z-Wave Protocol over SSL/TLS";
	case 41794:
		return "Crestron Control Port";
	case 41795:
		return "Crestron Terminal Port";
	case 41796:
		return "Crestron Secure Control Port";
	case 41797:
		return "Crestron Secure Terminal Port";
	case 42508:
		return "Computer Associates network discovery protocol";
	case 42509:
		return "CA discovery response";
	case 42510:
		return "CA eTrust RPC";
	case 42999:
		return "API endpoint for search application";
	case 43000:
		return "Receiver Remote Control";
	case 43188:
		return "REACHOUT";
	case 43189:
		return "NDM-AGENT-PORT";
	case 43190:
		return "IP-PROVISION";
	case 43191:
		return "Reconnoiter Agent Data Transport";
	case 43210:
		return "Shaper Automation Server Management";
	case 43438:
		return "Reserved";
	case 43439:
		return "EQ3 firmware update";
	case 43440:
		return "Cisco EnergyWise Management";
	case 43441:
		return "Cisco NetMgmt DB Ports";
	case 44123:
		return "Z-Wave Secure Tunnel";
	case 44321:
		return "PCP server (pmcd)";
	case 44322:
		return "PCP server (pmcd) proxy";
	case 44323:
		return "HTTP binding for Performance Co-Pilot client API";
	case 44444:
		return "Cognex DataMan Management Protocol";
	case 44445:
		return "Acronis Backup Gateway service port";
	case 44544:
		return "Reserved";
	case 44553:
		return "REALbasic Remote Debug";
	case 44600:
		return "Reserved";
	case 44818:
		return "EtherNet/IP messaging IANA assigned this well-formed service name as a replacement for EtherNet/IP-2.";
	case 44900:
		return "M3DA is used for efficient machine-to-machine communications";
	case 45000:
		return "Nuance AutoStore Status Monitoring Protocol (data transfer)";
	case 45001:
		return "Nuance AutoStore Status Monitoring Protocol (secure data transfer)";
	case 45002:
		return "Redspeed Status Monitor";
	case 45045:
		return "Remote application control protocol";
	case 45054:
		return "InVision AG";
	case 45514:
		return "ASSIA CloudCheck WiFi Management System";
	case 45678:
		return "EBA PRISE";
	case 45824:
		return "Server for the DAI family of client-server products";
	case 45825:
		return "Qpuncture Data Access Service";
	case 45966:
		return "SSRServerMgr";
	case 46336:
		return "Listen port used for Inedo agent communication";
	case 46998:
		return "Connection between a desktop computer or server and a signature tablet to capture handwritten signatures";
	case 46999:
		return "MediaBox Server";
	case 47000:
		return "Message Bus";
	case 47001:
		return "Windows Remote Management Service";
	case 47100:
		return "Reserved";
	case 47557:
		return "Databeam Corporation";
	case 47624:
		return "Direct Play Server";
	case 47806:
		return "ALC Protocol";
	case 47808:
		return "Building Automation and Control Networks";
	case 47809:
		return "Reserved";
	case 48000:
		return "Nimbus Controller";
	case 48001:
		return "Nimbus Spooler";
	case 48002:
		return "Nimbus Hub";
	case 48003:
		return "Nimbus Gateway";
	case 48004:
		return "NimbusDB Connector";
	case 48005:
		return "NimbusDB Control";
	case 48048:
		return "Juliar Programming Language Protocol";
	case 48049:
		return "3GPP Cell Broadcast Service Protocol";
	case 48050:
		return "WeFi Access Network Discovery and Selection Function";
	case 48128:
		return "Image Systems Network Services";
	case 48129:
		return "Bloomberg locator";
	case 48556:
		return "com-bardac-dw";
	case 48619:
		return "iqobject";
	case 48653:
		return "Robot Raconteur transport";
	case 49000:
		return "Matahari Broker";
	case 49001:
		return "Nuance Unity Service Request Protocol";
	case 49150:
		return "InSpider System";
	default:
		if (port >= 49152 && port <= 65535)
			return "Dynamic";
		return "Unknown";
	};
}
