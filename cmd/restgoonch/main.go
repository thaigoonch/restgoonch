package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	grpcgoonch "github.com/thaigoonch/restgoonch/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/keepalive"
)

var (
	grpcPort            = 9000
	promPort            = 9092
	reg                 = prometheus.NewRegistry()
	grpcMetrics         = grpc_prometheus.NewServerMetrics()
	customMetricCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "restgoonch_server_handle_count",
		Help: "Total number of RPCs handled on the goonch server.",
	}, []string{"name"})
)

func init() {
	reg.MustRegister(grpcMetrics, customMetricCounter)
	_, err := reg.Gather()
	if err != nil {
		log.Fatalf("Prometheus metric registration error: %v", err)
	}
}

func main() {
	fmt.Println("restgoonch waiting for client requests...")
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		grpclog.Fatalf("Failed to listen on port %d: %v", grpcPort, err)
	}

	// Create an http server for prometheus
	httpServer := &http.Server{
		Handler: promhttp.HandlerFor(reg, promhttp.HandlerOpts{}),
		Addr:    fmt.Sprintf(":%d", promPort)}

	// Create a gRPC server
	s := grpcgoonch.Server{}
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(grpcMetrics.UnaryServerInterceptor()),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionAge: time.Second * 31,
		}),
	)
	grpcgoonch.RegisterServiceServer(grpcServer, &s)
	grpcMetrics.InitializeMetrics(grpcServer)

	// Start http server for prometheus
	go func() {
		if err := httpServer.ListenAndServe(); err != nil {
			log.Fatalf("Unable to start an http server on port %d: %v", promPort, err)
		}
	}()

	if err := grpcServer.Serve(lis); err != nil {
		grpclog.Fatalf("Failed to serve gRPC server over port %d: %v", grpcPort, err)
	}
}
