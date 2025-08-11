file:
  with builtins; let
    matched_group = match
      ''.+\.version = "([^"]+)",.+''
      (readFile file);
  in
    elemAt matched_group 0
