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
#  along with this program; if not, visit the following URL:
#  http://www.gnu.org/copyleft/gpl.html

package PGP::GPG::MessageProcessor;

use 5.005;

use strict;
no strict 'refs';
use English;
use Carp;
use Fcntl;
use vars qw/ $VERSION /;
use Fatal qw/ open close pipe fcntl /;
use IO::Handle;
1;

$VERSION = '0.4.5';

use constant DEBUG => 0;

$OUTPUT_AUTOFLUSH = 1;

sub new {
  my $proto  = shift;
  my $class = ref ( $proto ) || $proto;
  my $self = 
    { gpg_program   => 'gpg',
      encrypt       =>  0,  # do not encrypt
      sign          =>  0,  # do not sign.
      passphrase    => '',  # secret-key passphrase
      interactive   =>  1,  # have user interact directly with GnuPG
      recipients    => [],  # encryption recipients.
      armor         =>  0,  # do not armor
      clearsign     =>  0,  # do not clearsign.
      symmetric     =>  0,  # do not only symmetrically encrypt
      secretKeyID   => '',  # GnuPG decides.
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




sub passphrase_test {
  my $self = shift;
  
  print STDERR "begin passphrase_test()\n" if DEBUG;
  
  $self->{passphrase} = shift if scalar @_;
  
  croak 'No passphrase defined to test!'
    unless $self->{passphrase};
  
  my $input      = new IO::Handle;
  my $output     = new IO::Handle;
  my $err        = new IO::Handle;
  my $status     = new IO::Handle;
  my $passphrase = new IO::Handle;
  
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
  
  my $in_fh  = new IO::Handle;
  my $out_fh = new IO::Handle;
  my $err_fh = defined $err ? new IO::Handle : ">&STDERR";
  
  my $pid = $self->$function( $in_fh, $out_fh, $err_fh );
  
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
  
  waitpid( $pid, 0 );
  
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
  
  unshift ( @{ $options }, '--default-key', $self->{secretKeyID} )
    if $self->{secretKeyID};
  
  unshift @{ $options }, '--batch', '--no-tty'
    unless $self->{interactive};
  
  unshift ( @{ $options }, '--homedir', $self->{homedir} )
    if $self->{homedir};
  
  unshift ( @{ $options }, @{ $self->{extraArgs} } )
    if scalar @{ $self->{extraArgs} };
  
  unshift @{ $options }, $self->{gpg_program};
  
  $stdin  = "<&STDIN"  unless $stdin;
  $stdout = ">&STDOUT" unless $stdout;
  $stderr = ">&STDERR" unless $stderr;
  
  
  # if they didn't give us a status filehandle, we'll
  # just create a dummy one to use, and discard the contents
  my $gave_status_handle = $status;
  $status = new IO::Handle  unless $gave_status_handle;
  
  my $passphrase_handle = new IO::Handle;
  
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
  
  my $child_read       = new IO::Handle;
  my $child_write      = new IO::Handle;
  my $child_err        = new IO::Handle;
  my $child_status     = new IO::Handle;
  my $child_passphrase = new IO::Handle;
  
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
      my $tmp = new IO::Handle;
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

PGP::GPG::MessageProcessor - supply object methods for interacting with GnuPG


=head1 SYNOPSIS

  use IO::Handle;
  use PGP::GPG::MessageProcessor;

  $mp = new PGP::GPG::MessageProcessor;

  $mp->{encrypt}    = $boolean;
  $mp->{sign}       = $boolean;

  $mp->{recipients} = [ 'keyID', ... ];

  $mp->{passphrase} = $passphrase;
  $success          = $mp->passphrase_test( $passphrase);

  $input  = new IO::Handle; # These could be be a Symbol::gensym
  $output = new IO::Handle;
  $error  = '';             # It becomes ">&STDERR".
  $status = new IO::Handle;

  $pid = $mp->cipher( $input, $output, $error, $status );
  
  print $input @plaintext;
  close $input;

  @ciphertext = <$output>;
  @error      = <$error>;
  @status     = <$status>;

  $input  = "<&STDIN";     # read from stdin; could also just be ''
  $output = '';            # write to stdout

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

  $mp = new PGP::GPG::MessageProcessor { encrypt => 1,
                                        symmetric => 1 }



=head1 DESCRIPTION

The purpose of B<PGP::GPG::MessageProcessor> is to provide a simple,
object-oriented interface to GnuPG, the GNU Privacy Guard,
and any other implementation of PGP that uses
the same syntax and piping mechanisms.

Normal usage involves creating a new object via B<new()>, making some settings
such as B<$passphase>, B<$armor>, or B<$recipients>, and then committing these
with B<cipher()> or B<decipher()>.

The interface to B<cipher()> and B<decipher()> is modelled after
B<IPC::Open3>, a base Perl module.  In fact, most of the inter-process
communication code in this module is modelled after B<IPC::Open3>.


=head1 METHODS

=over 4

=item new()

Creates a new object.  One can pass in data members with
values using an anonymous hash.  See the synopsis for an example.

=item passphrase_test( [ $passphrase ] )

Tests if B<$passphase> (already set
or passed as an argument) is valid for the secret
key currently selected.  Sets B<$passphrase> to any passed argument.

=item cipher( $stdin, [ $stdout, [ $stderr, [ $status ] ] ] )

This is a committal method; that is, it looks at all the previously-set
data members, and calls GnuPG accordingly for encrypting or signing streams.
The interface for this method is similar to B<IPC::Open3>'s interface;
please read it for gritty details.
Basically, handles are passed in, and they are attached to the GnuPG process.
This interface is a lot more lenient, however.
For example, B<$stdin>, B<$stdout>, or B<$stderr> is eliminated, or false,
its respective 'natural' file handle is used.
That is, if B<$stderr> is elminated, all of GnuPG's stderr is piped
out to your stderr; if B<$stdin> is eliminated, GnuPG reads from your stdin.
B<$status> reads from GnuPG's B<--status-fd> option,
and has no 'natural' backup; that is, if it is eliminated,
the output is not piped to any other filehandle.
To detect success or failure, one can either see if the output handle is
eof, or, for more detail, read from B<$status>, looking for error statements..
B<encrypt()> and B<sign()> are aliases for this subroutine,
for ease of readibility.

=item decipher( $stdin, [ $stdout, [ $stderr, [ $status ] ] ] )

This is just like B<cipher()>, described above, except that
it is used for decrypting or verifying streams.
B<decrypt()> and B<verify()> are aliases for this subroutine,
for ease of readibility.

=back


=head1 DATA MEMBERS

=over 4

=item $encrypt

If true, the message will be encrypted.
Default is false.

=item $sign

If true, the message will be signed.
Default is false.

=item $recipients

A reference to an array of keyIDs GnuPG will encrypt to.
Default is null.

=item $passphrase

GnuPG will use B<$passphrase> for signing and decrypting.
This does not have to be set if B<$interactive> is set,
or the operation, such as signature verification, does not require it.
Default is null.

=item $interactive

Setting this will allow the user to interact
directly with GnuPG such as to enter passphrases.
This is desired for maximum security,
so that passphrases are not held in memory.
Default is true.

=item $armor

If true, GnuPG will produce an armored output.
Default is false.

=item $clearsign

If true, GnuPG will produce clear-signed messages.
Default is false.

=item $symmetric

If true, GnuPG will only symmetrically (conventionally) encrypt.
This option is supposed to be used in addition to a true value for B<$encrypt>.
If true, B<$recipients> will be disregarded.
Default is false.

=item $secretKeyID

The secret key GnuPG will use for signing and passphrase testing.
GnuPG will choose the default key if unset.
Default is null.

=item $comment

This option fills defines what comment is put into the comment
field of messages.
Default is null; GnuPG determines.

=item $homedir

This option determines the argument to GnuPG's B<--homedir> option.
Default is null; GnuPG determines.

=item $gpg_program

This is the path which is used to call GnuPG.
Default is 'gpg', which will find GnuPG if it is in your B<$PATH>;

=item $extraArgs

A reference to an array of any other possible arguments
Please note that if you wish to have multiple options,
including ones that are divided up among two arguments,
such as B<--cipher-algo>, which takes a second argument, an integer,
divide up the arguments into different elements in the array reference.
See the synopsis for an example.

=back


=head1 NOTES

Unless B<$interactive> is true, B<$passphrase> must be set, either
directly, or indirectly through B<passphrase_test()>.

Some settings have no effect in some situations.  For instance,
B<$encrypt> has no effect if B<decipher()> is called.

This module does not override any options in what GnuPG considers
to be its option file.

You should wait for the $pid returned by B<cipher()> or B<decipher()>,
using the B<wait()> or B<waitpid()> calls, or else you may end
up accumulating zombies.

=head1 BACKWARDS COMPATIBILITY

Older versions of this module used a sick array-ref method of
passing data around.  That interface has been dropped, in
favor of the cleaner, more efficient, easier to use
passed-filehandle method.
However, for a couple of revisions,
the array-ref interface will still be allowed,
but heavily discouraged.
Expect this compatibility to be dropped, and change your code
to use the new interface described in this manpage.


=head1 SECURITY NOTES

Nothing fancy here for security such as memory-locking.

This module solely uses pipes to interact with GnuPG.

For maximum passphrase security, B<$interactive> should be true, forcing
the user to input the passphrase directly to GnuPG.


=head1 PROBLEMS/BUGS

Nothing fancy here for security such as memory-locking.

This documentation is probably pretty bad.  Please let me know
of errors.


=head1 AUTHOR

Frank J. Tobin <ftobin@uiuc.edu>

=over 4

=item OpenPGP fingerprint:

fingerprint: 4F86 3BBB A816 6F0A 340F  6003 56FF D10A 260C 4FA3

=back


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
along with this program; if not, visit the following URL:
http://www.gnu.org/copyleft/gpl.html

=cut
