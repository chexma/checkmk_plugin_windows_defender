# check_windows_defender
# Version 0.1
# Andre Eckstein - Andre.Eckstein@Bechtle.com

write-output("<<<windows_defender:sep(58)>>>")
$defender_status = get-mpcomputerstatus
write-output($defender_status)
