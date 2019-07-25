int __fastcall decstr(int result, int a2, char a3)
{
  int v3; // r4@0
  char v4; // r5@0
  signed int v5; // r6@1
  unsigned int v6; // r3@1

  v5 = 10924;
  v6 = 4;
def_B3A821D8:
  while ( v6 != 5 )
  {
    while ( 2 )
    {
      switch ( v6 )
      {
        case 2u:
          ++v3;
          v6 = 24 - (v5 - 37 * ((unsigned int)(56680 * v5) >> 21));
          goto def_B3A821D8;
        case 3u:
          v6 = v3 < a2;
          goto def_B3A821D8;
        case 1u:
          v5 = 3795;
          *(_BYTE *)(result + v3) = *(_BYTE *)(result + v3 + 2) ^ v4;
          v6 = 2;
          continue;
        case 4u:
          v3 = 0;
          v6 = 3;
          v4 = *(_BYTE *)(result + 1) ^ a3;
          continue;
        case 0u:
          *(_BYTE *)(result + v3) = 0;
          return result;
        default:
          goto def_B3A821D8;
      }
    }
  }
  return result;
}