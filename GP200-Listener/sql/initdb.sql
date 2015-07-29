--
-- GP200 DATABASE - setup
--

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";

--
-- Database: `gp200`
--

-- --------------------------------------------------------

--
-- Tabel structuur voor tabel `Events`
--

DROP TABLE IF EXISTS `Events`;
CREATE TABLE IF NOT EXISTS `Events` (
  `record_id` int(10) unsigned NOT NULL auto_increment,
  `gps_date` datetime NOT NULL,
  `imei` bigint(20) NOT NULL,
  `switch` tinyint(3) unsigned NOT NULL,
  `event_id` smallint(5) unsigned NOT NULL,
  `latitude` decimal(10,7) unsigned NOT NULL,
  `longtitude` decimal(10,7) unsigned NOT NULL,
  `IO` tinyint(3) unsigned NOT NULL,
  `speed` tinyint(3) unsigned NOT NULL,
  `direction` tinyint(3) unsigned NOT NULL,
  `altitude` tinyint(4) unsigned NOT NULL,
  `power` decimal(3,1) unsigned NOT NULL,
  `battery` decimal(3,1) unsigned NOT NULL,
  `distance` int(7) unsigned NOT NULL,
  `satellites` tinyint(2) unsigned NOT NULL,
  `gpssignal` tinyint(1) unsigned NOT NULL,
  `gsmsignal` tinyint(1) unsigned NOT NULL,
  `trusted` tinyint(1) unsigned NOT NULL,
  `raw_data` tinyblob NOT NULL,
  `extra` longblob NOT NULL,
  PRIMARY KEY  (`record_id`),
  KEY `gps_date` (`gps_date`),
  KEY `imei` (`imei`),
  KEY `switch` (`switch`),
  KEY `event_id` (`event_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 AUTO_INCREMENT=697 ;

-- --------------------------------------------------------

--
-- Tabel structuur voor tabel `Events_debug`
--

DROP TABLE IF EXISTS `Events_debug`;
CREATE TABLE IF NOT EXISTS `Events_debug` (
  `datetime` datetime NOT NULL,
  `payload` blob NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
