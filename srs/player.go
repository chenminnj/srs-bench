// The MIT License (MIT)
//
// # Copyright (c) 2021 Winlin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
package srs

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/pion/logging"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3/pkg/media/h265writer"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ossrs/go-oryx-lib/errors"
	"github.com/ossrs/go-oryx-lib/logger"
	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v3"
	"github.com/pion/webrtc/v3/pkg/media"
	"github.com/pion/webrtc/v3/pkg/media/h264writer"
	"github.com/pion/webrtc/v3/pkg/media/ivfwriter"
	"github.com/pion/webrtc/v3/pkg/media/oggwriter"
)

type customLogger struct{}

// Print all messages except trace
func (c customLogger) Trace(msg string) { fmt.Printf("customLogger Trace: %s\n", msg) }
func (c customLogger) Tracef(format string, args ...interface{}) {
	c.Trace(fmt.Sprintf(format, args...))
}
func (c customLogger) Debug(msg string) { fmt.Printf("customLogger Debug: %s\n", msg) }
func (c customLogger) Debugf(format string, args ...interface{}) {
	c.Debug(fmt.Sprintf(format, args...))
}
func (c customLogger) Info(msg string) { fmt.Printf("customLogger Info: %s\n", msg) }
func (c customLogger) Infof(format string, args ...interface{}) {
	c.Info(fmt.Sprintf(format, args...))
}
func (c customLogger) Warn(msg string) { fmt.Printf("customLogger Warn: %s\n", msg) }
func (c customLogger) Warnf(format string, args ...interface{}) {
	c.Warn(fmt.Sprintf(format, args...))
}
func (c customLogger) Error(msg string) {
	fmt.Printf("customLogger Error: %s\n", msg)
}
func (c customLogger) Errorf(format string, args ...interface{}) {
	c.Error(fmt.Sprintf(format, args...))
}

// customLoggerFactory satisfies the interface logging.LoggerFactory
// This allows us to create different loggers per subsystem. So we can
// add custom behavior
type customLoggerFactory struct{}

func (c customLoggerFactory) NewLogger(subsystem string) logging.LeveledLogger {
	fmt.Printf("Creating logger for %s \n", subsystem)
	return customLogger{}
}

func myInterfaceFilter(ifName string) bool {
	if ifName == "ens33" {
		return true
	}
	return false
}

// @see https://github.com/pion/webrtc/blob/master/examples/save-to-disk/main.go
func startPlay(ctx context.Context, r, dumpAudio, dumpVideo string, enableAudioLevel, enableTWCC bool, pli int) error {
	ctx = logger.WithContext(ctx)

	logger.Tf(ctx, "Run play url=%v, audio=%v, video=%v, audio-level=%v, twcc=%v",
		r, dumpAudio, dumpVideo, enableAudioLevel, enableTWCC)

	// For audio-level.
	webrtcNewPeerConnection := func(configuration webrtc.Configuration) (*webrtc.PeerConnection, error) {
		m := &webrtc.MediaEngine{}
		if err := m.RegisterDefaultCodecs(); err != nil {
			return nil, err
		}

		videoRTCPFeedback := []webrtc.RTCPFeedback{{"goog-remb", ""}, {"transport-cc", ""}, {"ccm", "fir"}, {"nack", ""}, {"nack", "pli"}}
		codec := webrtc.RTPCodecParameters{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: "video/H265", ClockRate: 90000, RTCPFeedback: videoRTCPFeedback},
			PayloadType:        104,
		}
		if err := m.RegisterCodec(codec, webrtc.RTPCodecTypeVideo); err != nil {
			return nil, err
		}

		for _, extension := range []string{sdp.SDESMidURI, sdp.SDESRTPStreamIDURI, sdp.TransportCCURI} {
			if extension == sdp.TransportCCURI && !enableTWCC {
				continue
			}
			if err := m.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{URI: extension}, webrtc.RTPCodecTypeVideo); err != nil {
				return nil, err
			}
		}

		// https://github.com/pion/ion/issues/130
		// https://github.com/pion/ion-sfu/pull/373/files#diff-6f42c5ac6f8192dd03e5a17e9d109e90cb76b1a4a7973be6ce44a89ffd1b5d18R73
		for _, extension := range []string{sdp.SDESMidURI, sdp.SDESRTPStreamIDURI, sdp.AudioLevelURI} {
			if extension == sdp.AudioLevelURI && !enableAudioLevel {
				continue
			}
			if err := m.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{URI: extension}, webrtc.RTPCodecTypeAudio); err != nil {
				return nil, err
			}
		}

		i := &interceptor.Registry{}
		if err := webrtc.RegisterDefaultInterceptors(m, i); err != nil {
			return nil, err
		}

		s := webrtc.SettingEngine{
			LoggerFactory: customLoggerFactory{},
		}
		s.SetInterfaceFilter(myInterfaceFilter)

		api := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithInterceptorRegistry(i), webrtc.WithSettingEngine(s))
		return api.NewPeerConnection(configuration)
	}
	pc, err := webrtcNewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return errors.Wrapf(err, "Create PC")
	}

	var receivers []*webrtc.RTPReceiver
	defer func() {
		pc.Close()
		for _, receiver := range receivers {
			receiver.Stop()
		}
	}()

	pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionRecvonly,
	})
	pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionRecvonly,
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return errors.Wrapf(err, "Create Offer")
	}

	if err := pc.SetLocalDescription(offer); err != nil {
		return errors.Wrapf(err, "Set offer %v", offer)
	}

	answer, err := apiRtcRequest(ctx, "/rtc/v1/play", r, offer.SDP)
	if err != nil {
		return errors.Wrapf(err, "Api request offer=%v", offer.SDP)
	}

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer, SDP: answer,
	}); err != nil {
		return errors.Wrapf(err, "Set answer %v", answer)
	}

	var da media.Writer
	var dv_vp8 media.Writer
	var dv_h264 media.Writer
	var dv_h265 media.Writer
	defer func() {
		if da != nil {
			da.Close()
		}
		if dv_vp8 != nil {
			dv_vp8.Close()
		}
		if dv_h264 != nil {
			dv_h264.Close()
		}
		if dv_h265 != nil {
			dv_h265.Close()
		}
	}()

	handleTrack := func(ctx context.Context, track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) error {
		// Send a PLI on an interval so that the publisher is pushing a keyframe
		go func() {
			if track.Kind() == webrtc.RTPCodecTypeAudio {
				return
			}

			if pli <= 0 {
				return
			}

			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(pli) * time.Second):
					_ = pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{
						MediaSSRC: uint32(track.SSRC()),
					}})
				}
			}
		}()

		receivers = append(receivers, receiver)

		codec := track.Codec()

		trackDesc := fmt.Sprintf("channels=%v", codec.Channels)
		if track.Kind() == webrtc.RTPCodecTypeVideo {
			trackDesc = fmt.Sprintf("fmtp=%v", codec.SDPFmtpLine)
		}
		if headers := receiver.GetParameters().HeaderExtensions; len(headers) > 0 {
			trackDesc = fmt.Sprintf("%v, header=%v", trackDesc, headers)
		}
		logger.Tf(ctx, "Got track %v, pt=%v, tbn=%v, %v",
			codec.MimeType, codec.PayloadType, codec.ClockRate, trackDesc)

		if codec.MimeType == "audio/opus" {
			logger.Wf(ctx, "audio %v pt=%v", codec.MimeType, codec.PayloadType)
			if da == nil && dumpAudio != "" {
				if da, err = oggwriter.New(dumpAudio, codec.ClockRate, codec.Channels); err != nil {
					return errors.Wrapf(err, "New audio dumper")
				}
				logger.Tf(ctx, "Open ogg writer file=%v, tbn=%v, channels=%v",
					dumpAudio, codec.ClockRate, codec.Channels)
			}

			if err = writeTrackToDisk(ctx, da, track); err != nil {
				return errors.Wrapf(err, "Write audio disk")
			}
		} else if codec.MimeType == "video/VP8" {
			if dumpVideo != "" && !strings.HasSuffix(dumpVideo, ".ivf") {
				return errors.Errorf("%v should be .ivf for VP8", dumpVideo)
			}

			if dv_vp8 == nil && dumpVideo != "" {
				if dv_vp8, err = ivfwriter.New(dumpVideo); err != nil {
					return errors.Wrapf(err, "New video dumper")
				}
				logger.Tf(ctx, "Open ivf writer file=%v", dumpVideo)
			}

			if err = writeTrackToDisk(ctx, dv_vp8, track); err != nil {
				return errors.Wrapf(err, "Write video disk")
			}
		} else if codec.MimeType == "video/H264" {
			if dumpVideo != "" && !strings.HasSuffix(dumpVideo, ".h264") {
				return errors.Errorf("%v should be .h264 for H264", dumpVideo)
			}

			if dv_h264 == nil && dumpVideo != "" {
				if dv_h264, err = h264writer.New(dumpVideo); err != nil {
					return errors.Wrapf(err, "New video dumper")
				}
				logger.Tf(ctx, "Open h264 writer file=%v", dumpVideo)
			}

			if err = writeTrackToDisk(ctx, dv_h264, track); err != nil {
				return errors.Wrapf(err, "Write video disk")
			}
		} else if codec.MimeType == "video/H265" {
			if dumpVideo != "" && !strings.HasSuffix(dumpVideo, ".h265") {
				return errors.Errorf("%v should be .h265 for H265", dumpVideo)
			}

			if dv_h265 == nil && dumpVideo != "" {
				if dv_h265, err = h265writer.New(dumpVideo); err != nil {
					return errors.Wrapf(err, "New video dumper")
				}
				logger.Tf(ctx, "Open h265 writer file=%v", dumpVideo)
			}

			if err = writeTrackToDisk(ctx, dv_h265, track); err != nil {
				return errors.Wrapf(err, "Write video disk")
			}
		} else {
			logger.Wf(ctx, "Ignore track %v pt=%v", codec.MimeType, codec.PayloadType)
		}
		return nil
	}

	ctx, cancel := context.WithCancel(ctx)
	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		err = handleTrack(ctx, track, receiver)
		if err != nil {
			codec := track.Codec()
			err = errors.Wrapf(err, "Handle  track %v, pt=%v", codec.MimeType, codec.PayloadType)
			cancel()
		}
	})

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		logger.If(ctx, "ICE state %v", state)

		if state == webrtc.ICEConnectionStateFailed || state == webrtc.ICEConnectionStateClosed {
			if ctx.Err() != nil {
				return
			}

			logger.Wf(ctx, "Close for ICE state %v", state)
			cancel()
		}
	})

	// Wait for event from context or tracks.
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				gStatRTC.PeerConnection = pc.GetStats()
			}
		}
	}()

	wg.Wait()
	return err
}

var rtpHeadTimestampPre uint32
var timeUnixPre int64

func writeTrackToDisk(ctx context.Context, w media.Writer, track *webrtc.TrackRemote) error {
	for ctx.Err() == nil {
		pkt, _, err := track.ReadRTP()

		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.Wrapf(err, "Read RTP")
		}
		var naluType byte
		if track.Kind() == webrtc.RTPCodecTypeVideo {
			if track.Codec().MimeType == "video/H265" {
				naluType = pkt.Payload[0] & 0x7E
			} else {
				naluType = pkt.Payload[0] & 0x1F
			}

			if naluType != 0 && naluType != 2 {
				//logger.Wf(ctx, "naluType %v", naluType)
				//logger.Wf(ctx, "pkt length:%v Payload:%v", len(pkt.Payload), pkt.Payload[:10])
			}

			if e := parseSei(ctx, pkt); e != nil {
				logger.Wf(ctx, "parseSei %vB err %+v", len(pkt.Payload), e)
			}
		} else {
			timeUnix := time.Now().UnixMicro()
			//logger.Wf(ctx, "audio pkt timestamp diff %v, receive diff: %v", pkt.Header.Timestamp-rtpHeadTimestampPre, (timeUnix-timeUnixPre)/1000)
			timeUnixPre = timeUnix
			rtpHeadTimestampPre = pkt.Header.Timestamp
		}
		if w == nil {
			continue
		}
		if err := w.WriteRTP(pkt); err != nil {
			if len(pkt.Payload) <= 2 {
				continue
			}
			logger.Wf(ctx, "Ignore write RTP %vB err %+v", len(pkt.Payload), err)
		}
	}

	return ctx.Err()
}

const (
	seiNALUType   = 6
	stapaNALUType = 24
	fuaNALUType   = 28

	fuaHeaderSize       = 2
	stapaHeaderSize     = 1
	stapaNALULengthSize = 2

	fuaStartBitmask = 0x80

	naluHeader = 2
)

func parseSei(ctx context.Context, pkt *rtp.Packet) error {
	if len(pkt.Payload) == 0 {
		return errors.New("pkt.PayLoad length is zero!")
	}

	// sei: nal_unit_type = 6 ;STAP-A :nal_unit_type = 24 ;分片单元 nal_unit_type = 28
	naluType := pkt.Payload[0] & 0x1F
	switch {
	case naluType == seiNALUType:
		timeStamp := strings.Split(string(pkt.Payload[1+naluHeader+16:len(pkt.Payload)-2]), ":")
		if len(timeStamp) != 2 || timeStamp[0] != "ts" {
			return nil
		}
		//logger.Wf(ctx,"1 sei info is %s",timeStamp[1])
		timeStamp64, _ := strconv.ParseInt(timeStamp[1], 10, 64)
		logger.Wf(ctx, "I frame delay %d ms", time.Now().UnixNano()/1000000-timeStamp64)

	case naluType == stapaNALUType:
		currOffset := int(stapaHeaderSize)

		for currOffset < len(pkt.Payload) {
			naluSize := int(binary.BigEndian.Uint16(pkt.Payload[currOffset:]))
			currOffset += stapaNALULengthSize

			if len(pkt.Payload) < currOffset+naluSize {
				return fmt.Errorf("packet is not large enough STAP-A declared size(%d) is larger than buffer(%d)", naluSize, len(pkt.Payload)-currOffset)
			}

			subNALUType := pkt.Payload[currOffset] & 0x1F
			//logger.Wf(ctx,"subNALUType is %d ,naluSize is %d, pkt length is %d",subNALUType,naluSize,len(pkt.Payload) )
			if subNALUType == seiNALUType {
				logger.Wf(ctx, "2 sei info is %s", string(pkt.Payload[currOffset:currOffset+naluSize]))
			}

			currOffset += naluSize
		}

	case naluType == fuaNALUType:
		if len(pkt.Payload) < fuaHeaderSize {
			return errors.New("packet is not large enough!")
		}
		if pkt.Payload[1]&fuaStartBitmask != 0 {
			fragmentedNaluType := pkt.Payload[1] & 0x1F

			//logger.Wf(ctx,"fragmentedNaluType is %d ,naluSize is %d, pkt length is %d",fragmentedNaluType,len(pkt.Payload)-1,len(pkt.Payload) )
			if fragmentedNaluType == seiNALUType {
				logger.Wf(ctx, "fuaNALUType sei info is %s,nalu size is %d", string(pkt.Payload[fuaHeaderSize:]), len(pkt.Payload)-fuaHeaderSize)
			}
		}
	default:
		//logger.Wf(ctx,"default ,naluSize is %d,naluType is %d",len(pkt.Payload),naluType )
	}
	return nil
}
