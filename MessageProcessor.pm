package PGP::GPG::MessageProcessor;

use 5.004;

use strict;
use English;
use Carp;
use IPC::Open2;
use IPC::Open3;
use FileHandle;
use vars qw/ $VERSION /;

$VERSION = '0.3.3';

sub new {
  my $proto  = shift;
  my $class = ref ($proto) || $proto;
  my $self = 
    { encrypt       =>  0,  # do not encrypt
      sign          =>  0,  # do not sign.
      passphrase    => '',  # secret-key passphrase
      interactive   =>  1,  # have user interact directly with GPG
      recipients    => [],  # encryption recipients.
      armor         =>  0,  # do not armor
      clearsign     =>  0,  # do not clearsign.
      symmetric     =>  0,  # do not only symmetrically encrypt
      secretKeyID   => '',  # GPG decides.
      extraArgs     => [],  # Any optional user-defined optional arguments.
      comment       => '',
      pgp50compatibility => 0
    };
  bless( $self, $class );
  $self->_init( @_ ); 
  return $self;
}




sub _init {
  my $self = shift;
  if ( @_ ) {
    my %extra = @_;
    @{ $self }{ keys %extra } = values %extra;
  }
}





sub passphrasePrompt {
  my $self = shift;
  
  # Clear old passphrase - not sure if this really overwrites it or not.
  $self->{passphrase} = ('0' x 256);
  $self->{passphrase} = '';

  system 'stty sane -echo < /dev/tty';
  
  my $tty = new FileHandle '< /dev/tty';
  chomp ( my $line = $tty->getline() );
  system 'stty sane < /dev/tty';
  
  return $self->{passphrase} = $line;
}




sub passphraseTest {
  my $self = shift;
  
  if ( scalar @_ ) { $self->{passphrase} = shift @_; }
  
  unless ( $self->{passphrase} ) { croak 'No passphrase defined to test!'; }
  
  # Test passphrase
  my $PGPIN  = new FileHandle;
  my $PGPOUT = new FileHandle;
  my $PGPERR = new FileHandle;
  my @cmd = ( 'gpg', '--sign', '--passphrase-fd', '0' );
  if ( $self->{secretKeyID} )
    { push ( @cmd, '--default-key ', $self->{secretKeyID} ); }
  
  open3( $PGPIN, $PGPOUT, $PGPERR, @cmd );
  print $PGPIN $self->{passphrase}, $INPUT_RECORD_SEPARATOR;
  $PGPIN->close();
  $PGPERR->close();
  
  #   # Actually test if there is any out.
  if ( $PGPOUT->getline() ) {
    $PGPOUT->close();
    return 1;
  }
  
  else {
    $PGPOUT->close();
    return 0;
  }
}




sub cipher {
  my $self = shift;
  
  my @cmd = ( 'gpg' );
  
  unless ( $self->{encrypt} or $self->{sign} ) {
    croak 'Did not specify to encrypt or sign message.';
  }
  
  if ( $self->{encrypt} ) {
    push @cmd, '--encrypt';
  }
  if ( $self->{sign} ) {
    push @cmd, ( $self->{clearsign} ? '--clearsign' : '--sign' );
  }
  
  
  # Check for recipients
  if ( $self->{encrypt} ) {
    if ( scalar @{ $self->{recipients} } ) {
      # need to add --recipient to each recipient
      push
	@cmd, map { ( '--recipient' => $_ ) } @{ $self->{recipients} };
    }
    else {
      croak 'Must specify recipients for encryption';
    }
  }
  
  # Extraneous command-line parameters
  if ( $self->{armor} )           { push ( @cmd, '--armor' ); }
  if ( $self->{symmetric} and scalar @{ $self->{recipients} } ) {
    croak 'Cannot symmetrically encrypt and have recipients';
  }
  if ( $self->{symmetric} )    { push ( @cmd, '--symmetric' ); }
  
  if ( $self->{pgp50compatibility} ) {
    push ( @cmd, '--compress-algo', '1', '--force-v3-sigs' );
  }
  
  if ( $self->{comment} ) { push ( @cmd, '--comment', $self->{comment} ); }
  
  return $self->pipePGP( [ @cmd ], @_ );
}




sub verify {
  my $self = shift;
  
  my @cmd = ( 'gpg', '--decrypt' );
  
  return $self->pipePGP( [ @cmd ], @_ );
}




sub pipePGP {
  my $self = shift;
  
  my $cmd     = shift;
  my $USERIN  = shift;
  my $USEROUT = scalar @_ ? shift : undef;
  my $USERERR = scalar @_ ? shift : undef;
  
  # $PGPIN meant to be the FD providing both password and $USERIN
  my $PGPIN  = new FileHandle;
  my $PGPOUT = new FileHandle;
  my $PGPERR = new FileHandle;
  
  # additional stuff pertinent to both verifing and encrypting
  if ( not $self->{interactive} ) {
    push @{ $cmd }, '--batch', '--passphrase-fd', 0;
  }

  if ( $self->{secretKeyID} ) {
    push @{ $cmd }, '--default-key', $self->{secretKeyID};
  }
  
  if ( scalar @{ $self->{extraArgs} } ) {
    push @{ $cmd }, @{ $self->{extraArgs} };
  }
  

  # STDIN, STDOUT, STDERR user-selected
  if ( defined $USERERR ) { open3( $PGPIN, $PGPOUT, $PGPERR, @{ $cmd } ); }
  
  # STDIN, STDOUT, user-selected
  elsif (defined $USEROUT )  { open2( $PGPOUT, $PGPIN, @ { $cmd } ); }
  
  # One FH user-selected
  else { open2 ( $PGPOUT, $PGPIN, @{ $cmd } ); }
  
  # Non-interactive needs to print passphrase
  if ( not $self->{interactive} ) {
    $PGPIN->print( $self->{passphrase},
		   $INPUT_RECORD_SEPARATOR );
  }
  
  $PGPIN->print( @{ $USERIN } );
  
  # Close the input pipe
  $PGPIN->close();
  
  # Grab the out.
  if ( defined $USERERR ) {
    @{ $USEROUT } = $PGPOUT->getlines();
    @{ $USERERR } = $PGPERR->getlines();
    return scalar @{ $USEROUT };
  }
  elsif ( defined $USEROUT ) {
    @{ $USEROUT } = $PGPOUT->getlines();
    return scalar @{ $USEROUT };
  }
  else {
    @{ $USERIN } = $PGPOUT->getlines();
    return scalar @{ $USERIN };
  }
  
}
