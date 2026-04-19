package com.example.pinvault.demo

import org.junit.rules.TestWatcher
import org.junit.runner.Description

/**
 * Otomatik QA ekran görüntüsü rule'ü. Her test başında ve sonunda
 * AllureHelper.screenshot() çağırır — cihazın aktif ekranı PNG olarak
 * /data/local/tmp/pinvault-qa-evidence/ dizinine yazılır (app uninstall'dan
 * etkilenmez). Pipeline sonunda adb pull ile toplanır.
 *
 * Kullanım:
 *   @get:Rule val shots = QaScreenshotRule()
 */
class QaScreenshotRule : TestWatcher() {
    private var currentDescription: Description? = null

    override fun starting(description: Description) {
        currentDescription = description
    }

    /**
     * Test body bittikten sonra, ama scenario.close() çağrılmadan ÖNCE @After'dan
     * manuel çağrılır — activity hala ekranda. TestWatcher.succeeded()/finished()
     * @After'dan SONRA fires ettiği için timing çakışıyor, bu yüzden explicit hook.
     *
     *     @After fun tearDown() {
     *         qaScreenshots.capture("final_state")
     *         scenario?.close()
     *     }
     */
    fun capture(suffix: String = "end") {
        val d = currentDescription ?: return
        val name = "${d.className.substringAfterLast('.')}_${d.methodName}_$suffix"
        AllureHelper.screenshot(name)
    }

    override fun failed(e: Throwable, description: Description) {
        // Başarısız testlerde de son durumu yakala (activity hala açık olabilir).
        AllureHelper.screenshot("${description.className.substringAfterLast('.')}_${description.methodName}_fail")
        AllureHelper.attachText("${description.methodName}_error", e.stackTraceToString())
    }
}
