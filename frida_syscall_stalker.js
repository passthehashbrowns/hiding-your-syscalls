var modules = Process.enumerateModules()
var ntdll = modules[1]

var ntdllBase = ntdll.base
send("[*] Ntdll base: " + ntdllBase)
var ntdllOffset = ntdllBase.add(ntdll.size)
send("[*] Ntdll end: " + ntdllOffset)

var pNtAcceptConnectPort = Module.findExportByName('ntdll.dll', 'NtAcceptConnectPort');
Interceptor.attach(pNtAcceptConnectPort, {
    onEnter: function (args){}
})
const mainThread = Process.enumerateThreads()[0];
Process.enumerateThreads().map(t => {
Stalker.follow(t.id, {
  events: {
    call: false, // CALL instructions: yes please
    // Other events:
    ret: false, // RET instructions
    exec: false, // all instructions: not recommended as it's
                 //                   a lot of data
    block: false, // block executed: coarse execution trace
    compile: false // block compiled: useful for coverage
  },
  onReceive(events) {  
  },
 
  transform(iterator){
      let instruction = iterator.next()
      do{
        if(instruction.mnemonic == "syscall"){
            var addrInt = instruction.address.toInt32()
            //If the syscall is coming from somewhere outside the bounds of NTDLL
            //then it may be malicious
            if(addrInt < ntdllBase.toInt32() || addrInt > ntdllOffset.toInt32()){
                send("[+] Found a potentially malicious syscall")
                iterator.putCallout(onMatch)
            }
        }
      iterator.keep()
      } while ((instruction = iterator.next()) !== null)
  }
})
})

function onMatch(context){
    send("[+] Syscall number: " + context.rax)
}
