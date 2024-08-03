import kotlin.system.exitProcess

/***
 * Normal flow.
 */
fun main(args: Array<String>) {
    System.loadLibrary("rust_kotlin")

    val mnt = args[0]
    val dataDir = args[1]
    val password = args[2]

    println("mnt = $mnt")
    println("dataDir = $dataDir")

    val str = "Kotlin"

    val resHello = hello(str)
    println(resHello)

    try {
        println("Mounting...")
        mount(mnt, dataDir, password, true)
        Thread.sleep(3000)
        println("Mounted, press Ctrl+C to umount...")
        Thread.sleep(Long.MAX_VALUE)
        umountAll()
    } catch (e: Exception) {
        println(e)
        exitProcess(1)
    }
    println("Bye!")
}

/***
 * Simulated errors and dry-run.
 */
//fun main(args: Array<String>) {
//    System.loadLibrary("rust_kotlin")
//
//    val mnt = args[0]
//    val dataDir = args[1]
//    val password = args[2]
//
//    println("mnt = $mnt")
//    println("dataDir = $dataDir")
//
//    val str = "Kotlin"
//
//    val resHello = hello(str)
//    println(resHello)
//
//    try {
//        println("Mounting...")
//        state(simulateMountError = true)
//        try {
//            mount(mnt, dataDir, password, false)
//        } catch (e: Exception) {
//            println("Err: ${e.message}")
//        }
//
//        state(simulateMountError = false)
//        println("normal mount")
//        val handle = mount(mnt, dataDir, password, false)
//        Thread.sleep(5000)
//        state(simulateUmountError = true)
//        try {
//            umount(handle)
//        } catch (e: Exception) {
//            println("Err: ${e.message}")
//        }
//
//        state(simulateUmountError = false)
//        println("normal umount")
//        umount(handle)
//
//        state(dryRun = true)
//        println("dry run")
//        mount(mnt, dataDir, password, false)
//        Thread.sleep(5000)
//
//        state(dryRun = false)
//        println("normal mount")
//        mount(mnt, dataDir, password, false)
//        state(simulateUmountAllError = true)
//        try {
//            umountAll()
//        } catch (e: Exception) {
//            println("Err: ${e.message}")
//        }
//
//        state(simulateUmountAllError = true)
//
//        println("Mounted, press Ctrl+C to umount...")
//        Thread.sleep(Long.MAX_VALUE)
//        umountAll()
//    } catch (e: Exception) {
//        println("Err: ${e.message}")
//        println("Bye!")
//        exitProcess(1)
//    }
//}
