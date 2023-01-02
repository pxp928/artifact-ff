//
// Copyright 2022 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oci

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types"
	"github.com/regclient/regclient/types/ref"
)

const (
	OCIRegistryCollector = "OCIRegistryCollector"
)

type ociRegistryCollector struct {
	registry      string
	checkedDigest map[string][]string
	poll          bool
	interval      time.Duration
}

func NewOCIRegistryCollector(ctx context.Context, registry string, poll bool, interval time.Duration) *ociRegistryCollector {
	return &ociRegistryCollector{
		registry:      registry,
		checkedDigest: map[string][]string{},
		poll:          poll,
		interval:      interval,
	}
}

// RetrieveArtifacts get the artifacts from the collector source based on polling or one time
func (o *ociRegistryCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if o.poll {
		for {
			err := o.getReposAndFetch(ctx, docChannel)
			if err != nil {
				return err
			}
			// set interval to about 5 mins or more
			time.Sleep(o.interval)
		}
	} else {
		err := o.getReposAndFetch(ctx, docChannel)
		if err != nil {
			return err
		}
	}

	return nil
}

func (o *ociRegistryCollector) getReposAndFetch(ctx context.Context, docChannel chan<- *processor.Document) error {
	rcOpts := []regclient.Opt{}
	rcOpts = append(rcOpts, regclient.WithDockerCreds())
	rcOpts = append(rcOpts, regclient.WithDockerCerts())

	rc := regclient.New(rcOpts...)

	r, err := ref.New(o.registry)
	if err != nil {
		return fmt.Errorf("failed to parse ref %s: %v", r, err)
	}
	defer rc.Close(ctx, r)

	rl, err := rc.RepoList(ctx, o.registry)
	if err != nil && errors.Is(err, types.ErrNotImplemented) {
		return fmt.Errorf("registry %s does not support underlying _catalog API: %w", o.registry, err)
	}

	for _, repo := range rl.Repositories {
		r, err := ref.New(repo)
		if err != nil {
			return err
		}
		collectedTags, err := getTagList(ctx, rc, r)
		if err != nil {
			return err
		}
		for _, tag := range collectedTags {
			ociRepoCollector := NewOCIRepoCollector(ctx, repo, tag, false, time.Second)
			ociRepoCollector.checkedDigest = o.checkedDigest[repo]
			ociRepoCollector.RetrieveArtifacts(ctx, docChannel)
			o.checkedDigest[repo] = ociRepoCollector.checkedDigest
		}
	}
	return nil
}

// Type is the collector type of the collector
func (o *ociRegistryCollector) Type() string {
	return OCIRegistryCollector
}
