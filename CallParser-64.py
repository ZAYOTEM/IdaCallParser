import idautils
import idc
print("""
   _____      _ _   _____                         
  / ____|    | | | |  __ \        ZAYOTEM             
 | |     __ _| | | | |__) |_ _ _ __ ___  ___ _ __ 
 | |    / _` | | | |  ___/ _` | '__/ __|/ _ \ '__|
 | |___| (_| | | | | |  | (_| | |  \__ \  __/ |   
  \_____\__,_|_|_| |_|   \__,_|_|  |___/\___|_|  
  
   ---------------------------------------------------
   | Twitter: https://twitter.com/zayotem            |
   | Github: https://github.com/ZAYOTEM              |
   | Authors:Halil FILIK, Hakan SOYSAL, Fatih YILMAZ |
   ---------------------------------------------------
  """)
for ea in idautils.Segments():
    segend = idc.get_segm_attr(ea, idc.SEGATTR_END)
    start = ea
    while start < segend:
        idc.create_insn(start)
        start = idc.find_unknown(start+1, idc.SEARCH_DOWN)

idc.gen_file(idc.OFILE_LST, "output"+".lst", 1, idc.BADADDR, 0)
LST = open("output.lst","r")
OutputFile = open("output.txt","a")
OutputFile.write("""
   _____      _ _   _____                         
  / ____|    | | | |  __ \        ZAYOTEM             
 | |     __ _| | | | |__) |_ _ _ __ ___  ___ _ __ 
 | |    / _` | | | |  ___/ _` | '__/ __|/ _ \ '__|
 | |___| (_| | | | | |  | (_| | |  \__ \  __/ |   
  \_____\__,_|_|_| |_|   \__,_|_|  |___/\___|_|  
  
   ---------------------------------------------------
   | Twitter: https://twitter.com/zayotem            |
   | Github: https://github.com/ZAYOTEM              |
   | Authors:Halil FILIK, Hakan SOYSAL, Fatih YILMAZ |
   ---------------------------------------------------
  """+"\n\n")
query1="call"
query2=["    rax","    rbx","    rcx","    rdx","    rsi","    rdi","    rbp","    r8","    r9","    r10","    r11","    r12","    r13","    r14","    r15"]
for row in LST:
 if query1 in row:
   line=row.split(" ")
   for i in range(len(query2)):
    if query2[i] in row:
     line2=line[0]
     OutputFile.write("call "+query2[i]+"--->"+line2+"\n")

LST.close()
OutputFile.close()