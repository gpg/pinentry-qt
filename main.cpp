/*
   main.cpp - A (not yet) secure Qt 4 dialog for PIN entry.

   Copyright (C) 2002, 2008 Klarälvdalens Datakonsult AB (KDAB)
   Copyright (C) 2003 g10 Code GmbH
   Copyright 2007 Ingo Klöcker

   Written by Steffen Hansen <steffen@klaralvdalens-datakonsult.se>.
   Modified by Marcus Brinkmann <marcus@g10code.de>.
   Modified by Marc Mutz <marc@kdab.com>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pinentrydialog.h"
#include "pinentry.h"

#include <qapplication.h>
#include <QIcon>
#include <QString>
#include <qwidget.h>
#include <qmessagebox.h>
#include <QPushButton>

#include <stdio.h>
#include <stdlib.h>
#ifndef HAVE_W32CE_SYSTEM
# include <errno.h>
#endif

#ifdef HAVE_W32CE_SYSTEM
# include <winbase.h>
# include <winioctl.h>
#endif

#include <memory>
#include <stdexcept>

#ifdef FALLBACK_CURSES
#include <pinentry-curses.h>
#endif

static QString escape_accel( const QString & s ) {

  QString result;
  result.reserve( s.size() );

  bool afterUnderscore = false;

  for ( unsigned int i = 0, end = s.size() ; i != end ; ++i ) {
    const QChar ch = s[i];
    if ( ch == QLatin1Char( '_' ) )
      {
        if ( afterUnderscore ) // escaped _
          {
            result += QLatin1Char( '_' );
            afterUnderscore = false;
          }
        else // accel
          {
            afterUnderscore = true;
          }
      }
    else
      {
        if ( afterUnderscore || // accel
             ch == QLatin1Char( '&' ) ) // escape & from being interpreted by Qt
          result += QLatin1Char( '&' );
        result += ch;
        afterUnderscore = false;
      }
  }

  if ( afterUnderscore )
    // trailing single underscore: shouldn't happen, but deal with it robustly:
    result += QLatin1Char( '_' );

  return result;
}

/* Hack for creating a QWidget with a "foreign" window ID */
class ForeignWidget : public QWidget
{
public:
  explicit ForeignWidget( WId wid ) : QWidget( 0 )
  {
    QWidget::destroy();
    create( wid, false, false );
  }

  ~ForeignWidget()
  {
    destroy( false, false );
  }
};

namespace {
    class InvalidUtf8 : public std::invalid_argument {
    public:
        InvalidUtf8() : std::invalid_argument( "invalid utf8" ) {}
        ~InvalidUtf8() throw() {}
    };
}

static const bool GPG_AGENT_IS_PORTED_TO_ONLY_SEND_UTF8 = false;

static QString from_utf8( const char * s ) {
    const QString result = QString::fromUtf8( s );
    if ( result.contains( QChar::ReplacementCharacter ) )
      {
        if ( GPG_AGENT_IS_PORTED_TO_ONLY_SEND_UTF8 )
            throw InvalidUtf8();
        else
            return QString::fromLocal8Bit( s );
      }
    
    return result;
}

static int
qt_cmd_handler (pinentry_t pe)
{
  QWidget *parent = 0;

  /* FIXME: Add parent window ID to pinentry and GTK.  */
  if (pe->parent_wid)
    parent = new ForeignWidget ((WId) pe->parent_wid);

  int want_pass = !!pe->pin;

  const QString ok =
      pe->ok             ? escape_accel( from_utf8( pe->ok ) ) :
      pe->default_ok     ? escape_accel( from_utf8( pe->default_ok ) ) :
      /* else */           QLatin1String( "&OK" ) ;
  const QString cancel =
      pe->cancel         ? escape_accel( from_utf8( pe->cancel ) ) :
      pe->default_cancel ? escape_accel( from_utf8( pe->default_cancel ) ) :
      /* else */           QLatin1String( "&Cancel" ) ;
  const QString title =
      pe->title ? from_utf8( pe->title ) :
      /* else */  QLatin1String( "pinentry-qt4" ) ;
      

  if (want_pass)
    {
      PinEntryDialog pinentry (parent, 0, true, !!pe->quality_bar);

      pinentry.setPinentryInfo (pe);
      pinentry.setPrompt (escape_accel (from_utf8 (pe->prompt)) );
      pinentry.setDescription (from_utf8 (pe->description));
      if ( pe->title )
          pinentry.setWindowTitle( from_utf8( pe->title ) );

      /* If we reuse the same dialog window.  */
      pinentry.setPin (secqstring());

      pinentry.setOkText (ok);
      pinentry.setCancelText (cancel);
      if (pe->error)
	pinentry.setError (from_utf8 (pe->error));
      if (pe->quality_bar)
	pinentry.setQualityBar (from_utf8 (pe->quality_bar));
      if (pe->quality_bar_tt)
	pinentry.setQualityBarTT (from_utf8 (pe->quality_bar_tt));

      bool ret = pinentry.exec ();
      if (!ret)
	return -1;

      const secstring pinUtf8(pinentry.pin().toUtf8());
      const char *pin = pinUtf8.data();

      int len = strlen (pin);
      if (len >= 0)
	{
	  pinentry_setbufferlen (pe, len + 1);
	  if (pe->pin)
	    {
	      strcpy (pe->pin, pin);
	      return len;
	    }
	}
      return -1;
    }
  else
    {
      const QString desc  = pe->description ? from_utf8 ( pe->description ) : QString();
      const QString notok = pe->notok       ? escape_accel (from_utf8 ( pe->notok )) : QString();

      const QMessageBox::StandardButtons buttons =
          pe->one_button ? QMessageBox::Ok :
          pe->notok      ? QMessageBox::Yes|QMessageBox::No|QMessageBox::Cancel :
          /* else */       QMessageBox::Ok|QMessageBox::Cancel ;

      QMessageBox box( QMessageBox::Information, title, desc, buttons, parent );

      const struct {
          QMessageBox::StandardButton button;
          QString label;
      } buttonLabels[] = {
          { QMessageBox::Ok,     ok     },
          { QMessageBox::Yes,    ok     },
          { QMessageBox::No,     notok  },
          { QMessageBox::Cancel, cancel },
      };

      for ( size_t i = 0 ; i < sizeof buttonLabels / sizeof *buttonLabels ; ++i )
        if ( (buttons & buttonLabels[i].button) && !buttonLabels[i].label.isEmpty() )
            box.button( buttonLabels[i].button )->setText( buttonLabels[i].label );

      box.setIconPixmap( icon() );

      if ( !pe->one_button )
        box.setDefaultButton( QMessageBox::Cancel );

      box.show();
      raiseWindow( &box );

      const int rc = box.exec();

      if ( rc == QMessageBox::Cancel )
        pe->canceled = true;

      return rc == QMessageBox::Ok || rc == QMessageBox::Yes ;

    }
}

static int
qt_cmd_handler_ex (pinentry_t pe)
{
  try {
    return qt_cmd_handler (pe);
  } catch ( const InvalidUtf8 & ) {
    pe->locale_err = true;
    return pe->pin ? -1 : false ;
  } catch ( ... ) {
    pe->canceled = true;
    return pe->pin ? -1 : false ;
  }
}

pinentry_cmd_handler_t pinentry_cmd_handler = qt_cmd_handler_ex;


#ifdef HAVE_W32CE_SYSTEM
/* Create a pipe.  WRITE_END shall have the opposite value of the one
   pssed to _assuan_w32ce_prepare_pipe; see there for more
   details.  */
#define GPGCEDEV_IOCTL_MAKE_PIPE                                        \
  CTL_CODE (FILE_DEVICE_STREAMS, 2049, METHOD_BUFFERED, FILE_ANY_ACCESS)
static HANDLE
w32ce_finish_pipe (int rvid, int write_end)
{
  HANDLE hd;

  hd = CreateFile (L"GPG1:", write_end? GENERIC_WRITE : GENERIC_READ,
                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                   NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,NULL);
  if (hd != INVALID_HANDLE_VALUE)
    {
      if (!DeviceIoControl (hd, GPGCEDEV_IOCTL_MAKE_PIPE,
                            &rvid, sizeof rvid, NULL, 0, NULL, NULL))
        {
          DWORD lastrc = GetLastError ();
          fprintf (stderr, "rvid %d, DeviceIoControl() failed: rc=%d\n",
                   rvid, (int)GetLastError ());
          CloseHandle (hd);
          hd = INVALID_HANDLE_VALUE;
          SetLastError (lastrc);
        }
      else
        fprintf (stderr, "rvid %d, mapped to %p\n", rvid, hd);
    }
  else
    fprintf (stderr, "rvid %d, CreateFile(GPG1) failed: rc=%d\n",
             rvid, (int)GetLastError ());

  return hd;
}
#endif /*HAVE_W32CE_SYSTEM*/



/* WindowsCE uses a very strange way of handling the standard streams.
   There is a function SetStdioPath to associate a standard stream
   with a file or a device but what we really want is to use pipes as
   standard streams.  Despite that we implement pipes using a device,
   we would have some limitations on the number of open pipes due to
   the 3 character limit of device file name.  Thus we don't take this
   path.  Another option would be to install a file system driver with
   support for pipes; this would allow us to get rid of the device
   name length limitation.  However, with GnuPG we can get away be
   redefining the standard streams and passing the handles to be used
   on the command line.  This has also the advantage that it makes
   creating a process much easier and does not require the
   SetStdioPath set and restore game.  The caller needs to pass the
   rendezvous ids using up to three options:

     -&S0=<rvid> -&S1=<rvid> -&S2=<rvid>

   They are all optional but they must be the first arguments on the
   command line.  Parsing stops as soon as an invalid option is found.
   These rendezvous ids are then used to finish the pipe creation.*/
#ifdef HAVE_W32CE_SYSTEM
static void
parse_std_file_handles (int *argcp, char ***argvp)
{
  int argc = *argcp;
  char **argv = *argvp;
  const char *s;
  int fd;
  int i;
  int fixup = 0;

  if (!argc)
    return;

  for (argc--, argv++; argc; argc--, argv++)
    {
      s = *argv;
      fprintf (stderr, "parse_std_file_handles '%s'\n", s);
      if (*s == '-' && s[1] == '&' && s[2] == 'S'
          && (s[3] == '0' || s[3] == '1' || s[3] == '2')
          && s[4] == '=' 
          && (strchr ("-01234567890", s[5]) || !strcmp (s+5, "null")))
        {
          if (s[5] == 'n')
            fd = (int)(-1);
          else
            fd = (int)w32ce_finish_pipe (atoi (s+5), s[3] != '0');
          if (s[3] == '0' && fd != -1)
            pinentry_set_std_fd (0, fd);
          else if (s[3] == '1' && fd != -1)
            pinentry_set_std_fd (1, fd);
          fixup++;
        }
      else
        break;
    }

  if (fixup)
    {
      argc = *argcp;
      argc -= fixup;
      *argcp = argc;

      argv = *argvp;
      for (i=1; i < argc; i++)
        argv[i] = argv[i + fixup];
      for (; i < argc + fixup; i++)
        argv[i] = NULL;
    }


}
#endif /*HAVE_W32CE_SYSTEM*/


int
main (int argc, char *argv[])
{
#ifdef HAVE_W32CE_SYSTEM
  pinentry_set_std_fd (0, fileno (stdin));
  pinentry_set_std_fd (1, fileno (stdout));
  parse_std_file_handles (&argc, &argv);
#endif
  pinentry_init ("pinentry-qt-qt4");

  std::auto_ptr<QApplication> app;

#ifdef FALLBACK_CURSES
  if (!pinentry_have_display (argc, argv))
    pinentry_cmd_handler = curses_cmd_handler;
  else
#endif
    {
      /* Qt does only understand -display but not --display; thus we
         are fixing that here.  The code is pretty simply and may get
         confused if an argument is called "--display". */
      char **new_argv, *p;
      size_t n;
      int i, done;

      for (n=0,i=0; i < argc; i++)
        n += strlen (argv[i])+1;
      n++;
      new_argv = (char**)calloc (argc+1, sizeof *new_argv);
      if (new_argv)
        *new_argv = (char*)malloc (n);
      if (!new_argv || !*new_argv)
        {
#ifndef HAVE_W32CE_SYSTEM
          fprintf (stderr, "pinentry-qt-qt4: can't fixup argument list: %s\n",
                   strerror (errno));
#else
          /* Since WinCE does not show the stderr output we leave out a 
             GetLastError() message */
          fprintf (stderr, "pinentry-qt-qt4: can't fixup argument list"); 
#endif
          exit (EXIT_FAILURE);

        }
      for (done=0,p=*new_argv,i=0; i < argc; i++)
        if (!done && !strcmp (argv[i], "--display"))
          {
            new_argv[i] = strcpy (p, argv[i]+1);
            p += strlen (argv[i]+1) + 1;
            done = 1;
          }
        else
          {
            new_argv[i] = strcpy (p, argv[i]);
            p += strlen (argv[i]) + 1;
          }

      /* We use a modal dialog window, so we don't need the application
         window anymore.  */
      i = argc;
      app.reset (new QApplication (i, new_argv));
      const QIcon icon( QLatin1String( ":/document-encrypt.png" ) );
      app->setWindowIcon( icon );
    }


  /* Consumes all arguments.  */
  if (pinentry_parse_opts (argc, argv))
    {
      printf ("pinentry-qt-qt4 (pinentry) " /* VERSION */ "\n");
      return EXIT_SUCCESS;
    }
  else
    {
      return pinentry_loop () ? EXIT_FAILURE : EXIT_SUCCESS ;
    }

}
