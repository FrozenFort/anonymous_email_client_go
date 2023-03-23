// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.6.1
// source: broker_anony_email.proto

package broker_anony_email

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	AnonyEmailBroker_Attest_FullMethodName         = "/anony_email.AnonyEmailBroker/Attest"
	AnonyEmailBroker_SendAnonyEmail_FullMethodName = "/anony_email.AnonyEmailBroker/SendAnonyEmail"
)

// AnonyEmailBrokerClient is the client API for AnonyEmailBroker service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AnonyEmailBrokerClient interface {
	Attest(ctx context.Context, opts ...grpc.CallOption) (AnonyEmailBroker_AttestClient, error)
	SendAnonyEmail(ctx context.Context, in *AnonyEmailAddr, opts ...grpc.CallOption) (*Response, error)
}

type anonyEmailBrokerClient struct {
	cc grpc.ClientConnInterface
}

func NewAnonyEmailBrokerClient(cc grpc.ClientConnInterface) AnonyEmailBrokerClient {
	return &anonyEmailBrokerClient{cc}
}

func (c *anonyEmailBrokerClient) Attest(ctx context.Context, opts ...grpc.CallOption) (AnonyEmailBroker_AttestClient, error) {
	stream, err := c.cc.NewStream(ctx, &AnonyEmailBroker_ServiceDesc.Streams[0], AnonyEmailBroker_Attest_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &anonyEmailBrokerAttestClient{stream}
	return x, nil
}

type AnonyEmailBroker_AttestClient interface {
	Send(*Request) error
	Recv() (*Response, error)
	grpc.ClientStream
}

type anonyEmailBrokerAttestClient struct {
	grpc.ClientStream
}

func (x *anonyEmailBrokerAttestClient) Send(m *Request) error {
	return x.ClientStream.SendMsg(m)
}

func (x *anonyEmailBrokerAttestClient) Recv() (*Response, error) {
	m := new(Response)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *anonyEmailBrokerClient) SendAnonyEmail(ctx context.Context, in *AnonyEmailAddr, opts ...grpc.CallOption) (*Response, error) {
	out := new(Response)
	err := c.cc.Invoke(ctx, AnonyEmailBroker_SendAnonyEmail_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AnonyEmailBrokerServer is the server API for AnonyEmailBroker service.
// All implementations must embed UnimplementedAnonyEmailBrokerServer
// for forward compatibility
type AnonyEmailBrokerServer interface {
	Attest(AnonyEmailBroker_AttestServer) error
	SendAnonyEmail(context.Context, *AnonyEmailAddr) (*Response, error)
	mustEmbedUnimplementedAnonyEmailBrokerServer()
}

// UnimplementedAnonyEmailBrokerServer must be embedded to have forward compatible implementations.
type UnimplementedAnonyEmailBrokerServer struct {
}

func (UnimplementedAnonyEmailBrokerServer) Attest(AnonyEmailBroker_AttestServer) error {
	return status.Errorf(codes.Unimplemented, "method Attest not implemented")
}
func (UnimplementedAnonyEmailBrokerServer) SendAnonyEmail(context.Context, *AnonyEmailAddr) (*Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendAnonyEmail not implemented")
}
func (UnimplementedAnonyEmailBrokerServer) mustEmbedUnimplementedAnonyEmailBrokerServer() {}

// UnsafeAnonyEmailBrokerServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AnonyEmailBrokerServer will
// result in compilation errors.
type UnsafeAnonyEmailBrokerServer interface {
	mustEmbedUnimplementedAnonyEmailBrokerServer()
}

func RegisterAnonyEmailBrokerServer(s grpc.ServiceRegistrar, srv AnonyEmailBrokerServer) {
	s.RegisterService(&AnonyEmailBroker_ServiceDesc, srv)
}

func _AnonyEmailBroker_Attest_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(AnonyEmailBrokerServer).Attest(&anonyEmailBrokerAttestServer{stream})
}

type AnonyEmailBroker_AttestServer interface {
	Send(*Response) error
	Recv() (*Request, error)
	grpc.ServerStream
}

type anonyEmailBrokerAttestServer struct {
	grpc.ServerStream
}

func (x *anonyEmailBrokerAttestServer) Send(m *Response) error {
	return x.ServerStream.SendMsg(m)
}

func (x *anonyEmailBrokerAttestServer) Recv() (*Request, error) {
	m := new(Request)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _AnonyEmailBroker_SendAnonyEmail_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AnonyEmailAddr)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AnonyEmailBrokerServer).SendAnonyEmail(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AnonyEmailBroker_SendAnonyEmail_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AnonyEmailBrokerServer).SendAnonyEmail(ctx, req.(*AnonyEmailAddr))
	}
	return interceptor(ctx, in, info, handler)
}

// AnonyEmailBroker_ServiceDesc is the grpc.ServiceDesc for AnonyEmailBroker service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AnonyEmailBroker_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "anony_email.AnonyEmailBroker",
	HandlerType: (*AnonyEmailBrokerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SendAnonyEmail",
			Handler:    _AnonyEmailBroker_SendAnonyEmail_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Attest",
			Handler:       _AnonyEmailBroker_Attest_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "broker_anony_email.proto",
}
