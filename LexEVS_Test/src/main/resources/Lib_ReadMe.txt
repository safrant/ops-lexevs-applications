For the browser utils, it is easiest if you install them in your local maven repository

mvn install:install-file -Dfile=./browser-util.jar -DgroupId=gov.nih.nci.evs -DartifactId=browser-util -Dversion=1.0 -Dpackaging=jar -DgeneratePom=true

mvn install:install-file -Dfile=./metabrowser-extension-distributed-client-2.0.5.jar -DgroupId=org.LexGrid.lexevs.metabrowser -DartifactId=metabrowser-extension -Dversion=2.05 -Dpackaging=jar -DgeneratePom=true