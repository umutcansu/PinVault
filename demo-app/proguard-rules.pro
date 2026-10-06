# demo-app R8 rules — release build only (debug is not minified).
#
# No keep rules of its own: the activities are found through the manifest,
# view binding classes are referenced directly, and the library's rules
# (model.**, Gson types) arrive with the AAR's consumer-rules.pro.
#
# Debug logs are REMOVED from the release build (security review A-2): the
# demo logs host names, pin prefixes, client ids and error details. No Timber
# tree is planted in release (BuildConfig.DEBUG gate in the activities); the
# calls themselves go too, so the strings they build are not in the APK.

-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

-assumenosideeffects class timber.log.Timber {
    public static void v(...);
    public static void d(...);
    public static void i(...);
}
-assumenosideeffects class timber.log.Timber$Forest {
    public void v(...);
    public void d(...);
    public void i(...);
}
-assumenosideeffects class timber.log.Timber$Tree {
    public void v(...);
    public void d(...);
    public void i(...);
}
