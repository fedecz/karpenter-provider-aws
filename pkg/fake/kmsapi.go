/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fake

import (
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

type KMSAPIBehavior struct {
	DescribeKeyBehaviour MockedFunction[kms.DescribeKeyInput, kms.DescribeKeyOutput]
}

type KMSAPI struct {
	kmsiface.KMSAPI
	KMSAPIBehavior
}

func NewKMSAPI() *KMSAPI {
	return &KMSAPI{}
}

// Reset must be called between tests otherwise tests will pollute
// each other.
func (s *KMSAPI) Reset() {
	s.DescribeKeyBehaviour.Reset()
}

func (s *KMSAPI) DescribeKey(input *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
	return s.DescribeKeyBehaviour.Invoke(input, func(keyInput *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
		if strings.Contains(*input.KeyId, "alias/mykmskey") {
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kms.KeyMetadata{
					AWSAccountId: aws.String("222233334444"),
					Arn:          aws.String("arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-2345678901ab"),
					KeyId:        aws.String("1234abcd-12ab-34cd-56ef-2345678901ab"),
				},
			}, nil
		} else if strings.Contains(*input.KeyId, "alias/nonexisting") {
			return nil, errors.New("key does not exist")
		} else {
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kms.KeyMetadata{
					AWSAccountId: aws.String("111122223333"),
					Arn:          aws.String("arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"),
					KeyId:        aws.String("1234abcd-12ab-34cd-56ef-1234567890ab"),
				},
			}, nil
		}
	})
}
