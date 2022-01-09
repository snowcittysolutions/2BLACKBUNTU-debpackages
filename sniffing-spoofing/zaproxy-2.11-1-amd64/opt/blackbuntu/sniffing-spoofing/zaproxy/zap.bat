if exist "%USERPROFILE%\OWASP ZAP\.ZAP_JVM.properties" (
	set /p jvmopts=< "%USERPROFILE%\OWASP ZAP\.ZAP_JVM.properties"
) else (
	set jvmopts=-Xmx512m
)

java %jvmopts% -jar zap-2.11.1.jar %*
