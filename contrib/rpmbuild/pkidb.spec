Name:           pkidb
Version:        1.2.1
Release:        1%{?dist}
Summary:        PKI system with a SQL database and OCSP responder. This is the successor of python-pkidb written in Golang

Group:          System Environment/Daemons
License:        GPL
URL:            https://git.ypbind.de/cgit/pkidb
Source0:        https://git.ypbind.de/cgit/pkidb/snapshot/pkidb-1.2.1.tar.gz
# Note: Depending on the Go version shipped with the distribution, a more recent Go version should be used instead
BuildRequires:  golang

%define dbinit_dir      %{_datadir}/%{name}/initialisation/

# don't build debuginfo package
%define debug_package %{nil}

# Don't barf on missing build_id
%global _missing_build_ids_terminate_build 0

%description
PKI script for managing certificates. Certificates are stored
 in a database. Supported database backends are: 
 * PostgreSQL 
 * MySQL 
 * SQLite3

%prep
%setup -q

%build
make depend build strip


%install
make install DESTDIR=%{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE README.md
%{_bindir}/pkidb
%{_mandir}/man1/%{name}.1.gz
%{_sysconfdir}/pkidb/template.example
%{_sysconfdir}/pkidb/config.ini.example
%{dbinit_dir}/mysql.sql
%{dbinit_dir}/pgsql.sql
%{dbinit_dir}/sqlite.sql

%changelog
* Sat Jul 04 2020 Andreas Maus <andreas.maus@atos.net> - 1.2.1
- Allow for configuration of OCSP URIs and CA issuing URIs
  and add information to newly created certificates

