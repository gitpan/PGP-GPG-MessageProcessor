use ExtUtils::MakeMaker;

WriteMakefile
  ( AUTHOR       => 'Frank J. Tobin',
    ABSTRACT     => 'supply object methods for interacting with GnuPG',
    NAME         => 'PGP::GPG::MessageProcessor',
    VERSION_FROM => 'MessageProcessor.pm',
    dist => {
	     COMPRESS   => 'gzip', 
	     SUFFIX     => 'gz',
	    },
  );
