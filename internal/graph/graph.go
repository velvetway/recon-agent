// Package graph хранит активы разведки в Neo4j.
//
// Онтология (узлы и связи):
//
//	(Program)-[:HAS_SCOPE]->(Domain)
//	(Domain)-[:HAS_SUBDOMAIN]->(Subdomain)
//	(Subdomain)-[:RESOLVES_TO]->(IP)
//	(IP)-[:HAS_PORT]->(Port)
//	(Port)-[:RUNS]->(Service)
//	(Service)-[:HAS_FINDING]->(Finding)
//
// Каталог слабостей (справочник, не зависит от программы):
//
//	(CWE)-[:CHILD_OF]->(CWE)
//
// Прогоны и наблюдения (источник для архива, см. observation.go):
//
//	(Program)-[:HAS_RUN]->(Run)-[:HAS_OBSERVATION]->(Observation)
package graph

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Store — обёртка над драйвером Neo4j.
type Store struct {
	driver neo4j.DriverWithContext
}

// Config — параметры подключения к Neo4j.
type Config struct {
	URI      string
	Username string
	Password string
}

// New открывает подключение к Neo4j и проверяет его.
func New(ctx context.Context, cfg Config) (*Store, error) {
	driver, err := neo4j.NewDriverWithContext(
		cfg.URI,
		neo4j.BasicAuth(cfg.Username, cfg.Password, ""),
	)
	if err != nil {
		return nil, fmt.Errorf("создание драйвера neo4j: %w", err)
	}
	if err := driver.VerifyConnectivity(ctx); err != nil {
		return nil, fmt.Errorf("проверка связи с neo4j: %w", err)
	}
	return &Store{driver: driver}, nil
}

// Close закрывает подключение.
func (s *Store) Close(ctx context.Context) error {
	return s.driver.Close(ctx)
}

// InitSchema создаёт ограничения уникальности для ключевых узлов.
func (s *Store) InitSchema(ctx context.Context) error {
	constraints := []string{
		"CREATE CONSTRAINT program_name IF NOT EXISTS FOR (p:Program) REQUIRE p.name IS UNIQUE",
		"CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
		"CREATE CONSTRAINT subdomain_name IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.name IS UNIQUE",
		"CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (i:IP) REQUIRE i.addr IS UNIQUE",
		"CREATE CONSTRAINT service_url IF NOT EXISTS FOR (s:Service) REQUIRE s.url IS UNIQUE",
		"CREATE CONSTRAINT port_key IF NOT EXISTS FOR (p:Port) REQUIRE (p.ip, p.number, p.proto) IS UNIQUE",
		"CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (c:CWE) REQUIRE c.id IS UNIQUE",
		"CREATE CONSTRAINT run_id IF NOT EXISTS FOR (r:Run) REQUIRE r.id IS UNIQUE",
		"CREATE CONSTRAINT observation_id IF NOT EXISTS FOR (o:Observation) REQUIRE o.id IS UNIQUE",
		"CREATE INDEX observation_run IF NOT EXISTS FOR (o:Observation) ON (o.run_id)",
	}
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		for _, c := range constraints {
			if _, err := tx.Run(ctx, c, nil); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpsertProgram создаёт или обновляет узел программы.
func (s *Store) UpsertProgram(ctx context.Context, name, platform string) error {
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		_, err := tx.Run(ctx,
			"MERGE (p:Program {name: $name}) SET p.platform = $platform",
			map[string]any{"name": name, "platform": platform},
		)
		return err
	})
}

// StartRun записывает узел прогона (:Run) и привязывает его к программе.
// run_id этого прогона проставляется на всех активах, найденных в нём.
func (s *Store) StartRun(ctx context.Context, runID, program, profile string) error {
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		_, err := tx.Run(ctx, `
			MERGE (p:Program {name: $program})
			MERGE (r:Run {id: $run})
			SET r.profile = $profile, r.started_at = timestamp()
			MERGE (p)-[:HAS_RUN]->(r)
		`, map[string]any{"run": runID, "program": program, "profile": profile})
		return err
	})
}

// AddSubdomain записывает найденный поддомен и привязывает его к домену.
func (s *Store) AddSubdomain(ctx context.Context, parentDomain, subdomain, source, runID string) error {
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		_, err := tx.Run(ctx, `
			MERGE (d:Domain {name: $parent})
			MERGE (s:Subdomain {name: $sub})
			SET s.source = $source, s.discovered_at = timestamp(), s.run_id = $run
			MERGE (d)-[:HAS_SUBDOMAIN]->(s)
		`, map[string]any{"parent": parentDomain, "sub": subdomain, "source": source, "run": runID})
		return err
	})
}

// AddResolution связывает поддомен с IP-адресом (Subdomain-[:RESOLVES_TO]->IP).
func (s *Store) AddResolution(ctx context.Context, subdomain, ip, runID string) error {
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		_, err := tx.Run(ctx, `
			MERGE (s:Subdomain {name: $sub})
			MERGE (i:IP {addr: $ip})
			SET i.discovered_at = coalesce(i.discovered_at, timestamp()), i.run_id = $run
			MERGE (s)-[:RESOLVES_TO]->(i)
		`, map[string]any{"sub": subdomain, "ip": ip, "run": runID})
		return err
	})
}

// HTTPService — результат httpx-проба по хосту.
type HTTPService struct {
	Host       string
	URL        string
	StatusCode int
	Title      string
	WebServer  string
	Tech       []string
}

// AddHTTPService записывает результат HTTP-проба на узел Subdomain.
func (s *Store) AddHTTPService(ctx context.Context, svc HTTPService, runID string) error {
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		_, err := tx.Run(ctx, `
			MERGE (s:Subdomain {name: $host})
			MERGE (svc:Service {url: $url})
			SET svc.status_code = $status,
			    svc.title = $title,
			    svc.webserver = $webserver,
			    svc.tech = $tech,
			    svc.probed_at = timestamp(),
			    svc.run_id = $run
			MERGE (s)-[:RUNS]->(svc)
		`, map[string]any{
			"host":      svc.Host,
			"url":       svc.URL,
			"status":    int64(svc.StatusCode),
			"title":     svc.Title,
			"webserver": svc.WebServer,
			"tech":      svc.Tech,
			"run":       runID,
		})
		return err
	})
}

// AddPort записывает открытый порт на IP (IP-[:HAS_PORT]->Port).
func (s *Store) AddPort(ctx context.Context, ip string, port int, proto, service, runID string) error {
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		_, err := tx.Run(ctx, `
			MERGE (i:IP {addr: $ip})
			MERGE (p:Port {ip: $ip, number: $port, proto: $proto})
			SET p.service = $service, p.discovered_at = timestamp(), p.run_id = $run
			MERGE (i)-[:HAS_PORT]->(p)
		`, map[string]any{
			"ip":      ip,
			"port":    int64(port),
			"proto":   proto,
			"service": service,
			"run":     runID,
		})
		return err
	})
}

// CountSubdomains возвращает число известных поддоменов домена.
func (s *Store) CountSubdomains(ctx context.Context, domain string) (int64, error) {
	var count int64
	err := s.read(ctx, func(tx neo4j.ManagedTransaction) error {
		res, err := tx.Run(ctx, `
			MATCH (:Domain {name: $d})-[:HAS_SUBDOMAIN]->(s:Subdomain)
			RETURN count(s) AS c
		`, map[string]any{"d": domain})
		if err != nil {
			return err
		}
		rec, err := res.Single(ctx)
		if err != nil {
			return err
		}
		if v, ok := rec.Get("c"); ok {
			count = v.(int64)
		}
		return nil
	})
	return count, err
}

func (s *Store) write(ctx context.Context, work func(neo4j.ManagedTransaction) error) error {
	sess := s.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer sess.Close(ctx)
	_, err := sess.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return nil, work(tx)
	})
	return err
}

func (s *Store) read(ctx context.Context, work func(neo4j.ManagedTransaction) error) error {
	sess := s.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer sess.Close(ctx)
	_, err := sess.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return nil, work(tx)
	})
	return err
}
