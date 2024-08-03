import kotlin.system.exitProcess

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
        val handle = mount(mnt, dataDir, password, true)
        println("Mounted, press Ctrl+C to umount...")
        Thread.sleep(Long.MAX_VALUE)
        umountAll()
    } catch (e: Exception) {
        println(e)
        exitProcess(1)
    }
    println("Bye!")
}
