
all:
	@echo "use make  run to execute"
	mvn package

run:
	mvn -Dmaven.tomcat.port=8086 tomcat7:run-war

clean:
	mvn clean

