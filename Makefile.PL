use ExtUtils::MakeMaker;

WriteMakefile
  ( 'NAME'     => 'PGP::GPG::MessageProcessor',
    'VERSION_FROM'  => 'MessageProcessor.pm',
    'dist' => {
	       'COMPRESS'   => 'gzip', 
	       'SUFFIX'     => 'gz',
	      },
  );
