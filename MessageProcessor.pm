#  Copyright (C) 1999 Frank J. Tobin <ftobin@uiuc.edu>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


package PGP::GPG::MessageProcessor;

use 5.005;

use strict;
no strict 'refs';
use English;
use FileHandle;
use Carp;
use Symbol;
use Fcntl;
use Term::ReadKey;
use vars qw/ $VERSION /;
use Fatal qw/ open close pipe gensym fcntl /;
1;

$VERSION = '0.4.2';

use constant DEBUG => 0;

$OUTPUT_AUTOFLUSH = 1;

sub new {
  my $proto  = shift;
  my $class = ref ( $proto ) || $proto;
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
      homedir       => '',  # gnupg's home directory
      comment       => '',
      pgp50compatibility => 0  # ack, kludges!
    };
  bless( $self, $class );
  $self->_init( @_ ); 
  return $self;
}




sub _init( $ ) {
  my $self = shift;
  if ( @_ ) {
    my %extra = @_;
    @{ $self }{ keys %extra } = values %extra;
  }
}





sub passphrase_prompt {
  my $self = shift;
  
  print STDERR "begin passphrase_prompt()\n" if DEBUG;
  
  my $tty = new FileHandle "/dev/tty";
  
  # Clear old passphrase - not sure if this really overwrites it or not.
  # so we'll just try anyways
  $self->{passphrase} = '0' x 256;
  
  ReadMode 'noecho', $tty;
  $self->{passphrase} = ReadLine 0;
  chomp $self->{passphrase};
  ReadMode 'restore', $tty;
}




sub passphrase_test {
  my $self = shift;
  
  print STDERR "begin passphrase_test()\n" if DEBUG;
  
  $self->{passphrase} = shift if scalar @_;
  
  croak 'No passphrase defined to test!'
    unless $self->{passphrase};
  
  my $input      = gensym;
  my $output     = gensym;
  my $err        = gensym;
  my $status     = gensym;
  my $passphrase = gensym;
  
  # save this value; we most definitely want to be in non-interactive mode
  my $saved_interactive = $self->{interactive};
  $self->{interactive} = 0;
  
  $self->call_with_common_interface( [ '--sign' ],
				     $input, $output, $err, $status );
  
  close $input;
  
  # return this data member to its original setting
  $self->{interactive} = $saved_interactive;
  
  # all we realy want to check is the status fh
  while ( <$status> ) {
    print STDERR $_ if DEBUG;
    return 1 if /^\[GNUPG:\]\s*GOOD_PASSPHRASE/;
  }
  
  
  return 0;
}




sub wrap_array_usage {
  my ( $self, $function, $input, $output, $err ) = @_;
  
  print STDERR "begin wrap_array_usage()\n" if DEBUG;
  
  my $gave_output = defined $output;
  
  my $in_fh  = gensym;
  my $out_fh = gensym;
  my $err_fh = defined $err ? gensym : ">&STDERR";
  
  $self->$function( $in_fh, $out_fh, $err_fh );
  
  foreach ( @{ $input } ) {
    print $in_fh $_;
  }
  
  close $in_fh;
  
  push @{ $output }, $_ while <$out_fh>;
  close $out_fh;
  
  
  if ( defined $err ) {
    push @{ $err }, $_ while <$err_fh>;
    close $err_fh;
  }
  
  if ( not $gave_output ) {
    @{ $input } = @{ $output };
  }
  
  return scalar @{ $output };
}






sub cipher {
  my ( $self, @handles ) = @_;
  
  print STDERR "begin cipher()\n" if DEBUG;
  
  return $self->wrap_array_usage( 'cipher', @handles )
    if ref( $handles[0] ) eq 'ARRAY';
	  
  croak 'Did not specify to encrypt or sign message'
    unless $self->{encrypt} or $self->{sign};
  
  # we only get here if non-array things (hopefully filehandles)
  # were passed in
  
  my @options = ();
  
  if ( $self->{encrypt} ) {
    push @options, '--encrypt';
    
    if ( $self->{symmetric} ) {
      push @options, '--symmetric';
    }
    else {
      
      # we need to check that we have recipients
      croak 'Must specify recipients for encryption'
	unless scalar @{ $self->{recipients} };
      
      # need to add --recipient to each recipient
      push
	@options, map { ( '--recipient' => $_ ) } @{ $self->{recipients} };
      
    }
    
  }
  
  if ( $self->{sign} ) {
    if ( $self->{encrypt} or not $self->{clearsign} ) {
      push @options, '--sign';
    }
    else {
      push @options, '--clearsign';
    }
  }
  
  
  # Extraneous command-line parameters
  # armor?
  push @options, '--armor'
    if $self->{armor};
  
  # OpenPGP-incompatible PGP 5.0 compatibility
  push @options, '--compress-algo', '1', '--force-v3-sigs'
    if $self->{pgp50compatibility};
  
  push ( @options, '--comment', $self->{comment} )
    if $self->{comment};
  
  return $self->call_with_common_interface( [ @options ], @handles );
}

# these are just aliases for now
sub sign    {  my $self = shift;  $self->cipher( @_ ); }
sub encrypt {  my $self = shift;  $self->cipher( @_ ); }




sub decipher {
  my ( $self, @handles ) = @_;
  
  print STDERR "begin decipher()\n" if DEBUG;
  
  return $self->wrap_array_usage( 'decipher', @handles )
    if ref( $handles[0] ) eq 'ARRAY';
  
  return $self->call_with_common_interface( [ '--decrypt' ], @handles );
}


sub verify  { my $self = shift; return $self->decipher( @_ ); }
sub decrypt { my $self = shift; return $self->decipher( @_ ); }




sub call_with_common_interface {
  my ( $self, $options, $stdin, $stdout, $stderr, $status ) = @_;
  
  print STDERR "begin call_with_common_interface()\n" if DEBUG;
  
  unshift @{ $options }, 'gpg';
  
  push ( @{ $options }, '--default-key', $self->{secretKeyID} )
    if $self->{secretKeyID};
  
  push @{ $options }, '--batch', '--no-tty'
    unless $self->{interactive};
  
  push ( @{ $options }, '--homedir', $self->{homedir} )
    if $self->{homedir};
  
  push ( @{ $options }, @{ $self->{extraArgs} } )
    if scalar @{ $self->{extraArgs} };
  
  $stdin  = "<&STDIN"  unless $stdin;
  $stdout = ">&STDOUT" unless $stdout;
  $stderr = ">&STDERR" unless $stderr;
  
  
  # if they didn't give us a status filehandle, we'll
  # just create a dummy one to use, and discard the contents
  my $gave_status_handle = $status;
  $status = gensym  unless $gave_status_handle;
  
  my $passphrase_handle = gensym;
  
  my $pid = $self->attach_pipes( $options, $stdin, $stdout, $stderr,
				 $status, $passphrase_handle );
  

  if ( not $self->{interactive} and $self->{passphrase} ) {
    print STDERR "passing passphrase to process\n" if DEBUG;
    print $passphrase_handle $self->{passphrase}, "\n";
    close $passphrase_handle;
  }
  
  unless ( $gave_status_handle ) {
    print STDERR "closing unused status handle\n" if DEBUG;
    close $status;
  }
  
  return $pid;
  
}





sub attach_pipes {
  my ( $self, $command, $parent_write,
       $parent_read, $parent_err,
       $parent_status, $parent_passphrase ) = @_;
  
  print STDERR "begin attach_pipes()\n" if DEBUG;
  
  # Below is code derived heavily from
  # Marc Horowitz's IPC::Open3, a base Perl module
  
  # the following dupped_* variables are booleans
  my $dupped_parent_write      = ( $parent_write      =~ s/^[<>]&// );
  my $dupped_parent_read       = ( $parent_read       =~ s/^[<>]&// );
  my $dupped_parent_err        = ( $parent_err        =~ s/^[<>]&// );
  my $dupped_parent_status     = ( $parent_status     =~ s/^[<>]&// );
  my $dupped_parent_passphrase = ( $parent_passphrase =~ s/^[<>]&// );
  
  my $child_read       = gensym;
  my $child_write      = gensym;
  my $child_err        = gensym;
  my $child_status     = gensym;
  my $child_passphrase = gensym;
  
  pipe $child_read,       $parent_write      unless $dupped_parent_write;
  pipe $parent_read,      $child_write       unless $dupped_parent_read;
  pipe $parent_err,       $child_err         unless $dupped_parent_err;
  pipe $parent_status,    $child_status      unless $dupped_parent_status;
  pipe $child_passphrase, $parent_passphrase unless $dupped_parent_passphrase;
  
  print STDERR "forking\n" if DEBUG;
  
  my $pid = fork;
  
  croak "fork failed: $ERRNO" unless defined $pid;
  
  if ( $pid == 0 ) {     # child
    
    # If she wants to dup the kid's stderr onto her stdout I need to
    # save a copy of her stdout before I put something else there.
    if ( $parent_read ne $parent_err
	 and $dupped_parent_err
	 and fileno( $parent_err ) == fileno( STDOUT ) ) {
      my $tmp = gensym;
      open $tmp, ">&$parent_err";
      $parent_err = $tmp;
    }
    
    if ( $dupped_parent_write ) {
      open \*STDIN, "<&$parent_write"
	unless fileno( STDIN ) == fileno( $parent_write );
    }
    else {
      close $parent_write;
      open \*STDIN, "<&=" . fileno $child_read;
    }
    
    
    if ( $dupped_parent_read ) {
      open \*STDOUT, "<&$parent_read"
	unless fileno( STDOUT ) == fileno( $parent_read );
    }
    else {
      close $parent_read;
      open \*STDOUT, ">&=" . fileno $child_write;
    }
    
    if ( $parent_read ne $parent_err ) {
      
      # I have to use a fileno here because in this one case
      # I'm doing a dup but the filehandle might be a reference
      # (from the special case above).
      if ( $dupped_parent_err ) {
	open \*STDERR, ">&" . fileno $parent_err
	  unless fileno( STDERR ) == fileno( $parent_err );
      }
      else {
	close $parent_err;
	open \*STDERR, ">&" . fileno $child_err;
      }
      
    }
    else {
      open \*STDERR, ">&STDOUT" unless fileno( STDERR ) == fileno( STDOUT );
    }
    
    close $parent_status
      unless $dupped_parent_status;
    
    close $parent_passphrase
      unless $dupped_parent_passphrase;
    
    
    # we want these fh's to stay open after the exec
    fcntl( $child_status,     F_SETFD, 0 );
    fcntl( $child_passphrase, F_SETFD, 0 );
    
    push @{ $command }, "--passphrase-fd", fileno $child_passphrase
      if not $self->{interactive} and $self->{passphrase};
    
    push @{ $command }, "--status-fd", fileno $child_status;
    
    print STDERR "fork: executing ", join( ' ', @{ $command } ), "\n" if DEBUG;
    
    exec @{ $command } or croak "exec() error: $ERRNO";
  }
  
  # parent
  close $child_read       unless $dupped_parent_write;
  close $child_write      unless $dupped_parent_read;
  close $child_err        unless $dupped_parent_err;
  close $child_status     unless $dupped_parent_status;
  close $child_passphrase unless $dupped_parent_passphrase;
  
  # close write handle if it was a dup
  close $parent_write      if $dupped_parent_write;
  close $parent_passphrase if $dupped_parent_passphrase;
  
  # unbuffer pipes
  select( ( select( $parent_write ),      $OUTPUT_AUTOFLUSH = 1 )[0] );
  select( ( select( $parent_passphrase ), $OUTPUT_AUTOFLUSH = 1 )[0] );
  
  return $pid;
}


=head1 NAME

PGP::GPG::MessageProcessor - supply object methods for interacting with GPG.

=head1 SYNOPSIS

  use Symbol;                     # for gensym
  use PGP::GPG::MessageProcessor;

  $mp = new PGP::GPG::MessageProcessor;

  $mp->{encrypt}    = $boolean;
  $mp->{sign}       = $boolean;

  $mp->{recipients} = [ 'keyID', ... ];

  $mp->{passphrase} = $passphrase;
  $passphrase       = $mp->passphrase_prompt();
  $success          = $mp->passphrase_test( $passphrase);

  $input  = gensym;  # These could be a new IO::Handle or FileHandle
  $output = gensym;  # instead; import theses modules if you want them.
  $error  = '';      # Yes, youy can do this!  It becomes ">&STDERR".
  $status = gensym;

  $pid = $mp->cipher( $input, $output, $error, $status );
  
  print $input @plaintext;
  close $input;

  @ciphertext = <$output>;
  @error      = <$error>;
  @status     = <$status>;

  $input  = "<&STDIN";     # read from stdin; this could also just be ''
  $output = '';            # write to stdout; this could also be ">&STDOUT"

  $pid = $mp->decipher( $input, $output, $error );

  $mp->{interactive} = $boolean;
  $mp->{noTTY}       = $boolean;
  $mp->{armor}       = $boolean;
  $mp->{clearsign}   = $boolean
  $mp->{symmetric}   = $boolean;
  $mp->{secretKeyID} = $keyID;
  $mp->{comment}     = $string;
  $mp->{homedir}     = $pathname; # without shell expansions like ~
  $mp->{extraArgs}   = [ '--cipher-algo', 2 ];

  $mp = new PGP::GPG::MessageProcessor { encrypt => 1, symmetric => 1 }


=head1 DESCRIPTION

The purpose of I<PGP::GPG::MessageProcessor> is to provide a simple,
object-oriented interface to GPG, the GNU Privacy Guard,
and any other implementation of PGP that uses
the same syntax and piping mechanisms.

Normal usage involves creating a new object via I<new()>, making some settings
such as I<$passphase>, I<$armor>, or I<$recipients>, and then committing these
with I<cipher()> or I<decipher()>.

The interface to I<cipher()> and I<decipher()> is modelled after
IPC::Open3, a base Perl module.  In fact, most of the inter-process
communication code in this module is modelled after IPC::Open3.

=head1 DATA MEMBERS

=over 2

=item B<$encrypt>

If true, the message will be encrypted.
Default is false.

=item B<$sign>

If true, the message will be signed.
Default is false.

=item B<$recipients>

A reference to an array of keyIDs GPG will encrypt to.
Default is null.

=item B<$passphrase>

GPG will use I<$passphrase> for signing and decrypting.
This does not have to be set if I<$interactive> is set.
Default is null.

=item B<$interactive>

Setting this will allow the user to interact directly with
GPG such as to enter passphrases.
This is desired for maximum security, so that passphrases
are not held in memory.
Default is true.

=item B<$armor>

If true, GPG will produce an armored output.
Default is false.

=item B<$clearsign>

If true, GPG will produce clear-signed messages.
Default is false.

=item B<$symmetric>

If true, GPG will only symmetrically (conventionally) encrypt.
This option is supposed to be used in addition to a true value
for I<$encrypt>.
If true, I<$recipients> will be disregarded.
Default is false.

=item B<$secretKeyID>

The secret key GPG will use for signing and passphrase testing.
GPG will choose the default key if unset.
Default is null.

=item B<$comment>

This option fills defines what comment is put into the comment
field of messages.
Default is null; GPG determines.

=item B<$homedir>

This option determines the argument to GPG's --homedir option.
Default is null; GPG determines.

=item B<$extraArgs>

A reference to an array of any other possible arguments
Please note that if you wish to have multiple options,
including ones that are divided up among two arguments,
such as --cipher-algo, which takes a second argument, an integer,
divide up the arguments into different elements in the
array reference.  See the example in the synopsis for an example.


=back

=head1 METHODS

=over 2

=item B<new()>

Creates a new object.  One can pass in data members with
values using an anonymous hash.  See synopsis for an example.

=item B<passphrase_prompt()>

Prompts the user for a passphrase; uses Term::ReadKey
for non-echoed input.  Sets I<$passphrase> to any input by the user.

=item B<passphrase_test( [$passphrase] )>

Tests if I<$passphase> (already set
or passed as an argument) is valid for the secret
key currently selected.  Sets I<$passphrase> to any passed argument.

=item B<cipher( $stdin, [ $stdout, [ $stderr, [ $status ] ] ] )>

This is a committal method; that is, it looks at all the previously-set
data members, and calls gpg accordingly for encrypting or signing
streams.
The interface for this method is similar to IPC::Open3's interface;
please read it for gritty details.  Basically, filehandles are passed
in, and they are attached to the gpg process.
This interface is a lot more lenient, however.
If $stdin, $stdout, or $stderr is eliminated, or false,
its respective 'natural' file handle is used.  That is, if $stderr
is elminated, all of gpg's stderr is piped out to your stderr; if
$stdin is eliminated, gpg reads from your stdin.  $status
reads from gpg's --status-fd option, and has no 'natural' backup;
that is, if it is eliminated, the output is not piped to
any other filehandle.
To detect success or failure, one can either see if the output is
eof (a hack), or, preferrably, read from $status.  This will
give you the best, detailed output.
I<encrypt()> and I<sign()> are aliases for this subroutine,
for ease of readibility.

=item B<decipher( $stdin, [ $stdout, [ $stderr, [ $status ] ] ] )>

This is just like I<cipher()>, described above, except that
it is used for decrypting or verifying streams.
I<decrypt()> and I<verify()> are aliases for this subroutine,
for ease of readibility.

=back

=head1 NOTES

Unless I<$interactive> is true, I<$passphrase> must be set, either
directly, or through
I<passphase_prompt()>, or I<passphrase_test()>.

Some settings have no effect in some situations.  For instance,
I<$encrypt> has no effect if I<decipher()> is called.

This module does not override any options in what gpg considers
to be its option file, located in its homedir.

=head2 BACKWARDS COMPATIBILITY

Older versions of this module used a sick array-ref method of
passing data around.  That interface has been dropped, in
favor of the cleaner, more efficient, easier to use
passed-filehandle method.  However,
for a couple of revisions, the array-ref interface will
still be allowed, but heavily discouraged.  Expect
this compatibility to be dropped, and change your code
to use the new interface described in this manpage.


=head1 SECURITY NOTES

Nothing fancy here for security such as memory-locking.

This module solely uses pipes to interact with gpg.

For maximum passphrase security, I<$interactive> should be true, forcing
the user to input the passphrase directly to GPG.

=head1 PROBLEMS/BUGS

Nothing fancy here for security such as memory-locking.

This documentation is probably pretty bad.  Please let me know
of errors.

=head1 AUTHOR

Frank J. Tobin <ftobin@uiuc.edu>

fingerprint: 4F86 3BBB A816 6F0A 340F  6003 56FF D10A 260C 4FA3

=head1 COPYRIGHT

Copyright (C) 1999 Frank J. Tobin <ftobin@uiuc.edu>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

=cut
